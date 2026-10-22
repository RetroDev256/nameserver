// ----------------------------------------------------------------------------
// Custom nameserver - runs on port 53, uses UDP:
// - "rng": returns random number in [0, 2^32) - TXT and A
// - "x.rng": returns random number in [0, x) - TXT and A
// - "a.b.rng": returns random number in [a, a + b) - TXT and A
// ----------------------------------------------------------------------------

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// number of bytes in the DNS header - 6x 16-bit fields is 12 bytes
#define HEADER_SIZE 12
// 253 bytes is the max size of a parsed QNAME - first and last marker removed
#define QNAME_SIZE 253
// 512 bytes is the max size of a UDP DNS message - RFC 1035 2.3.4
#define DNS_BUF_SIZE 512
// CLASS value for the internet - RFC 1035 3.2.4
#define CLASS_IN 1

// TYPE values for resource records - RFC 1035 3.2.2
#define TYPE_A 1 // a host address
#define TYPE_TXT 16 // text strings

// DNS header definition - RFC 1035 4.1.1
struct dns_header {
    // 16 bit identifier that generates any kind of query
    uint16_t id;
    // QR, OPCODE, AA, TC, RD, RA, Z, and RCODE flags
    uint16_t flags;
    // u16 - number of entries in question section
    uint16_t qd_count;
    // u16 - number of records in answer section
    uint16_t an_count;
    // u16 - number of records in authority section
    uint16_t ns_count;
    // u16 - number of records in additional section
    uint16_t ar_count;
};

// ----------------------------------------------------------------------------
// Create and bind IPv4/IPv6 UDP socket on port 53, open to all interfaces.
// ----------------------------------------------------------------------------
int create_ns_socket() {
    // create an IPv6 UDP [SOCK_DGRAM + IPPROTO_UDP] socket
    int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) goto error;

    // explicitly accept both IPv4 and IPv6 packets
    int ipv6_only = 0, level = IPPROTO_IPV6, name = IPV6_V6ONLY;
    if (setsockopt(sock, level, name, &ipv6_only, sizeof(ipv6_only)))
        goto error;

    // describe local address to listen on
    struct sockaddr_in6 server_addr = {
        .sin6_family = AF_INET6, // IPv6 [and IPv4] addresses
        .sin6_port = htons(53), // listen on port 53 - DNS
        .sin6_addr = in6addr_any, // listen on all interfaces
    };

    // attach opened socket to that address and port
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)))
        goto error;

    return sock;

error:
    // display error message
    perror(NULL);
    // close any opened socket
    if (sock >= 0) close(sock);
    // terminate program with error
    exit(1);
}

// ----------------------------------------------------------------------------
// Parse a DNS question into a QNAME buffer, QTYPE integer, and QCLASS integer.
// Returns 0 on success, -1 on failure. Format defined in RFC 1035 4.1.2.
// ----------------------------------------------------------------------------
int parse_question(
    const uint8_t *const restrict packet,
    size_t *const restrict off,
    const size_t len,
    uint8_t *const restrict q_name,
    uint16_t *const restrict q_type,
    uint16_t *const restrict q_class
) {
    // there is no room for a question within the packet
    if (*off >= len) return -1;
    // the QNAME is empty, only the root label is present
    if (packet[*off] == 0) return -1;

    size_t write = 0;
    uint16_t target;
    int jumped = 0;
    size_t end;

    while (1) {
        // QNAME is not finished yet we ran out of bounds
        if (*off >= len) return -1;
        // read label length and advance past the byte
        uint8_t label = packet[(*off)++];
        // the root label has been found
        if (label == 0) break;

        // RFC 1035 4.1.4. Message compression
        switch (label & 0b11000000) {
            // normal labels - top bits 00
            case 0b00000000:
                // the packet is too small to have that label
                if (label > len - *off) return -1;
                // the QNAME is too large to be valid
                if (write + 1 + label > QNAME_SIZE) return -1;
                // write QNAME label separator
                if (write > 0) q_name[write++] = '.';
                // write QNAME label content
                memcpy(q_name + write, packet + *off, label);
                // advance read and write pointers
                write += label, *off += label;
                break;

            // compression pointers - top bits 11
            case 0b11000000:
                // ensure there is enough space for the pointer
                if (*off >= len) return -1;
                // continue reading labels from the target pointer
                target = ((label & 0b00111111) << 8) | packet[(*off)++];
                // only allow backwards jumps to prevent infinitely looping
                if (target >= *off - 2) return -1;
                // the question continues after the current reading head
                if (!jumped) jumped = 1, end = *off;
                // continue reading labels from the target pointer
                *off = target;
                break;

            // reserved for future use - top bits 01 or 10
            default:
                return -1;
        }
    }

    // the QNAME must not be empty
    if (write == 0) return -1;
    // restore the reading head if we jumped
    if (jumped) *off = end;
    // both QTYPE and QCLASS must fit in the packet
    if (4 > len - *off) return -1;

    // copy the QTYPE and convert to host endianness
    memcpy(q_type, packet + *off, 2);
    *q_type = ntohs(*q_type);
    *off += 2;

    // copy the QCLASS and convert to host endianness
    memcpy(q_class, packet + *off, 2);
    *q_class = ntohs(*q_class);
    *off += 2;

    // add a null-character delimiter to qname
    q_name[write] = 0;

    return 0;
}

// ----------------------------------------------------------------------------
// Write a response into output packet, with given name, type, TTL, and data.
// Returns 0 on success, -1 on failure. Format defined in RFC 1035 4.1.3.
// ----------------------------------------------------------------------------
int resource(
    uint8_t *const packet,
    size_t *const restrict off,
    const uint8_t *const name,
    const size_t name_len,
    const uint16_t type,
    const uint32_t time_to_live,
    const uint8_t *const restrict data,
    const uint16_t data_len
) {
    // there is no room for this response in the packet
    if (*off + name_len + data_len + 10 > DNS_BUF_SIZE) return -1;

    // write the name into the output packet
    memcpy(packet + *off, name, name_len);
    *off += name_len;

    // write the type into the output packet
    uint16_t type_network = htons(type);
    memcpy(packet + *off, &type_network, 2);
    *off += 2;

    // write the class into the output packet
    uint16_t class_network = htons(CLASS_IN);
    memcpy(packet + *off, &class_network, 2);
    *off += 2;

    // write the TTL into the output packet
    uint16_t ttl_network = htonl(time_to_live);
    memcpy(packet + *off, &ttl_network, 4);
    *off += 4;

    // write data length into output packet
    uint16_t len_network = htons(data_len);
    memcpy(packet + *off, &len_network, 2);
    *off += 2;

    // write the data into the output packet
    memcpy(packet + *off, data, data_len);
    *off += data_len;

    return 0;
}

// ----------------------------------------------------------------------------
// Encode TXT resource from a string. r_data must have room for 256 bytes.
// Returns 0 on success, -1 on failure.  Format defined in RFC 1035 3.3.14.
// ----------------------------------------------------------------------------
int encode_txt_resource(
    const char *const restrict text,
    uint8_t *const restrict r_data,
    uint16_t *const restrict r_data_len
) {
    size_t len = strlen(text);
    if (len > 255) return -1;

    r_data[0] = (uint8_t)len;
    memcpy(r_data + 1, text, len);
    *r_data_len = len + 1;
    return 0;
}

// ----------------------------------------------------------------------------
// Encode A resource from a string. r_data must have room for 4 bytes.
// Format defined in RFC 1035 3.4.1.
// ----------------------------------------------------------------------------
void encode_a_resource(
    const uint32_t value,
    uint8_t *const restrict r_data,
    uint16_t *const restrict r_data_len
) {
    uint32_t network = htonl(value);
    memcpy(r_data, &network, 4);
    *r_data_len = 4;
}

// ----------------------------------------------------------------------------
// Change the request header to a response header. RFC 1035 4.1.1.
// ----------------------------------------------------------------------------
void set_response(uint8_t *const buf, uint16_t an_count) {
    // copy OPCODE and RD, mark response and authority
    buf[2] = 0x84 | (buf[2] & 0x79);
    // clear RA, Z, and RCODE
    buf[3] = 0x00;

    // set the number of answers in the header
    an_count = htons(an_count);
    memcpy(buf + 6, &an_count, 2);

    // no records in the authority section
    buf[8] = 0x00, buf[9] = 0x00;
    // no records in the additional section
    buf[10] = 0x00, buf[11] = 0x00;
}

// ----------------------------------------------------------------------------
// Change the request header to a format-error response header. RFC 1035 4.1.1.
// ----------------------------------------------------------------------------
void set_format_error_response(uint8_t *const buf) {
    // copy OPCODE and RD, mark response and authority
    buf[2] = 0x84 | (buf[2] & 0x79);
    // set format-error
    buf[3] = 0x01;

    // no entries in the questions section
    buf[4] = 0x00, buf[5] = 0x00;
    // no records in the answer section
    buf[6] = 0x00, buf[7] = 0x00;
    // no records in the authority section
    buf[8] = 0x00, buf[9] = 0x00;
    // no records in the additional section
    buf[10] = 0x00, buf[11] = 0x00;
}

int main(void) {
    // create and bind IPv4/IPv6 UDP socket on port 53
    int sock = create_ns_socket();

    uint8_t buf[DNS_BUF_SIZE];

    // store address of an IPv4 or IPv6 client
    struct sockaddr_in6 client_addr;
    socklen_t ca_len = sizeof(client_addr);
    struct sockaddr *ca_ptr = (struct sockaddr *)&client_addr;

    while (1) {
        // recieve a DNS query and store client's address
        ssize_t n = recvfrom(sock, buf, DNS_BUF_SIZE, 0, ca_ptr, &ca_len);
        // ignore all incomplete packets (smaller than DNS header)
        if (n < HEADER_SIZE) goto format_error;

        struct dns_header header;
        // copy from buffer into the header
        memcpy(&header, buf, sizeof(header));
        // QR flag - ignore packets identifying as a response
        if (ntohs(header.flags) & 0x8000) goto format_error;
        // QDCOUNT - ignore packets not asking one question
        if (ntohs(header.qd_count) != 1) goto format_error;

        size_t off = HEADER_SIZE; // question starts after header
        uint8_t q_name[QNAME_SIZE + 1]; // +1 for null terminated string
        uint16_t q_type, q_class; // type and class of asked question

        int err = parse_question(buf, &off, n, q_name, &q_type, &q_class);
        const uint16_t rq_len = off - HEADER_SIZE - 4;
        const uint8_t *const raw_q = buf + HEADER_SIZE;

        // there was a problem parsing the question
        if (err) goto format_error;
        // the isn't asking for ordinary DNS data
        if (q_class != CLASS_IN) goto format_error;
        // change the packet so it can be used to respond to requests
        set_response(buf, 1);

        uint8_t r_data[256];
        uint16_t rd_len;

        switch (q_type) {
            case TYPE_TXT:
                err = encode_txt_resource("Hello, World!", r_data, &rd_len);
                if (err) goto format_error;
                break;
            case TYPE_A:
                encode_a_resource(0xFFBB7733, r_data, &rd_len);
                break;
        }

        // sending resource with 0 TTL to help prevent caching
        err = resource(buf, &off, raw_q, rq_len, q_type, 0, r_data, rd_len);

        // succeeded writing resource
        if (!err) goto send_response;

    format_error:
        set_format_error_response(buf);

    send_response:
        sendto(sock, buf, off, 0, ca_ptr, ca_len);
    }

    close(sock);
    return 0;
}
