#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

#define MAX_IFACE_NAME 100
#define PACKET_COUNT 1000
#define SQL_BATCH_SIZE 10
#define SNAP_LEN 65535

void clear_screen() {
    printf("\033[2J\033[H");
}

const char *get_next_header(const u_char *packet, int offset, int *next_header_offset) {
    struct ip6_ext *ext_header = (struct ip6_ext *)(packet + offset);
    int next_header = ext_header->ip6e_nxt;
    int ext_header_len = 8 + ext_header->ip6e_len * 8;

    *next_header_offset = offset + ext_header_len;

    if (next_header == IPPROTO_FRAGMENT) {
        struct ip6_frag *frag_header = (struct ip6_frag *)(packet + offset);
        next_header = frag_header->ip6f_nxt;
        *next_header_offset = offset + sizeof(struct ip6_frag);
    } else if (next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_ROUTING || next_header == IPPROTO_DSTOPTS) {
        return get_next_header(packet, *next_header_offset, next_header_offset);
    }

    return next_header == IPPROTO_TCP ? "TCP" :
           next_header == IPPROTO_UDP ? "UDP" :
           next_header == IPPROTO_ICMPV6 ? "ICMPv6" : "";
}

void collect_network_data(sqlite3 *db) {
    char iface[MAX_IFACE_NAME];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *iface_list, *iface_ptr;
    int iface_count = 0;

    // Find available network interfaces
    if (pcap_findalldevs(&iface_list, errbuf) == -1) {
        fprintf(stderr, "Error finding network interfaces: %s\n", errbuf);
        return;
    }

    while (1) {
        // Print available network interfaces
        printf("Available network interfaces:\n");
        for (iface_ptr = iface_list; iface_ptr != NULL; iface_ptr = iface_ptr->next) {
            printf("%d. %s\n", ++iface_count, iface_ptr->name);
        }

        // Get user's choice of network interface
        int choice;
        printf("Enter the number of the network interface to capture packets from: ");
        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "Invalid input. Please enter a valid number.\n");
            pcap_freealldevs(iface_list);
            return;
        }

        // Get the chosen network interface
        iface_ptr = iface_list;
        for (int i = 1; i < choice && iface_ptr != NULL; i++) {
            iface_ptr = iface_ptr->next;
        }

        if (iface_ptr == NULL) {
            printf("Invalid network interface choice. Please try again.\n");
            iface_count = 0;
        } else {
            break;
        }
    }

    strncpy(iface, iface_ptr->name, MAX_IFACE_NAME);
    pcap_freealldevs(iface_list);

    // Open the selected network interface for packet capture
    pcap_t *handle = pcap_open_live(iface, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening network interface %s: %s\n", iface, errbuf);
        return;
    }

    // Prepare SQL statement for inserting packet data
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO packets (date, time, src_ip, src_port, dst_ip, dst_port, protocol, packet_length) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error preparing SQL statement: %s\n", sqlite3_errmsg(db));
        pcap_close(handle);
        return;
    }

    // Capture packets
    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 0;

    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    while (packet_count < PACKET_COUNT) {
        packet = pcap_next(handle, &header);
        // After calling pcap_next
        // printf("Packet captured\n");
        if (packet == NULL) {
            fprintf(stderr, "Error capturing packet: %s\n", pcap_geterr(handle));
            continue;
        }

        // Check if the packet is an IP packet
        struct ether_header *eth_header = (struct ether_header *)packet;
        // After checking if the packet is an IP packet
        // printf("IP packet: %s\n", (ntohs(eth_header->ether_type) == ETHERTYPE_IP || ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) ? "Yes" : "No");
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP && ntohs(eth_header->ether_type) != ETHERTYPE_IPV6) {
            continue;
        }

        // Extract packet information
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        u_short src_port = 0;
        u_short dst_port = 0;
        const char *protocol = "";
        // After extracting packet information
        // printf("Source IP: %s\n", src_ip);
        // printf("Destination IP: %s\n", dst_ip);
        // printf("Protocol: %s\n", protocol);

        // Parse IPv4 or IPv6 packet
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        if (ip_header->ip_v == 4) {
            // IPv4 packet
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Parse TCP or UDP packet
            if (ip_header->ip_p == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                src_port = ntohs(tcp_header->th_sport);
                dst_port = ntohs(tcp_header->th_dport);
                protocol = "TCP";
            } else if (ip_header->ip_p == IPPROTO_UDP) {
                struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                src_port = ntohs(udp_header->uh_sport);
                dst_port = ntohs(udp_header->uh_dport);
                protocol = "UDP";
            } else if (ip_header->ip_p == IPPROTO_ICMP) {
                protocol = "ICMP";
            }
        } else if (ip_header->ip_v == 6) {
            // IPv6 packet
            struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
            inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

            // Handle IPv6 extension headers
            int next_header_offset;
            protocol = get_next_header(packet, sizeof(struct ether_header) + sizeof(struct ip6_hdr), &next_header_offset);

            if (strcmp(protocol, "TCP") == 0) {
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + next_header_offset);
                src_port = ntohs(tcp_header->th_sport);
                dst_port = ntohs(tcp_header->th_dport);
            } else if (strcmp(protocol, "UDP") == 0) {
                struct udphdr *udp_header = (struct udphdr *)(packet + next_header_offset);
                src_port = ntohs(udp_header->uh_sport);
                dst_port = ntohs(udp_header->uh_dport);
            }
        } else {
            // Unsupported IP version
            fprintf(stderr, "Unsupported IP version: %d\n", ip_header->ip_v);
            continue;
        }

        // Insert packet data into the database
        char date[11];
        char time[9];
        strftime(date, sizeof(date), "%Y-%m-%d", localtime(&(header.ts.tv_sec)));
        strftime(time, sizeof(time), "%H:%M:%S", localtime(&(header.ts.tv_sec)));

        sqlite3_bind_text(stmt, 1, date, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, time, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, src_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, src_port);
        sqlite3_bind_text(stmt, 5, dst_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 6, dst_port);
        sqlite3_bind_text(stmt, 7, protocol, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 8, header.len);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            fprintf(stderr, "Error inserting packet data: %s\n", sqlite3_errmsg(db));
        }

        sqlite3_reset(stmt);

        if (++packet_count % SQL_BATCH_SIZE == 0) {
            sqlite3_exec(db, "COMMIT TRANSACTION", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
        }
    }

    sqlite3_exec(db, "COMMIT TRANSACTION", NULL, NULL, NULL);
    sqlite3_finalize(stmt);
    pcap_close(handle);
    printf("Packet collection completed.\n");
}


void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}


void view_database(sqlite3 *db) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT * FROM packets";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error preparing SQL statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    printf("Database contents:\n");
    printf("%-10s %-8s %-39s %-5s %-39s %-5s %-7s %-6s\n",
           "Date", "Time", "Source IP", "SPort", "Destination IP", "DPort", "Proto", "Length");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *date = (const char *)sqlite3_column_text(stmt, 0);
        const char *time = (const char *)sqlite3_column_text(stmt, 1);
        const char *src_ip = (const char *)sqlite3_column_text(stmt, 2);
        int src_port = sqlite3_column_int(stmt, 3);
        const char *dst_ip = (const char *)sqlite3_column_text(stmt, 4);
        int dst_port = sqlite3_column_int(stmt, 5);
        const char *protocol = (const char *)sqlite3_column_text(stmt, 6);
        int packet_length = sqlite3_column_int(stmt, 7);

        printf("%-10s %-8s %-39s %-5d %-39s %-5d %-7s %-6d\n",
               date, time, src_ip, src_port, dst_ip, dst_port, protocol, packet_length);
    }

    sqlite3_finalize(stmt);

    printf("Press Enter to continue...");
    clear_input_buffer();
}

void clear_database(sqlite3 *db) {
    const char *sql = "DELETE FROM packets";
    char *err_msg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "Error clearing database: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("Database cleared.\n");
    }

    printf("Press Enter to continue...");
    clear_input_buffer();
}



void export_database(sqlite3 *db) {
    int format_choice;
    printf("Choose the export format:\n");
    printf("1. CSV\n");
    printf("2. JSON\n");
    printf("3. TEXT\n");
    printf("Enter your choice: ");
    if (scanf("%d", &format_choice) != 1) {
        fprintf(stderr, "Invalid input. Please enter a valid number.\n");
        clear_input_buffer();
        return;
    }

    sqlite3_stmt *stmt;
    const char *sql = "SELECT * FROM packets";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error preparing SQL statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    FILE *file;
    char filename[100];

    switch (format_choice) {
        case 1:
            strcpy(filename, "network_data.csv");
            file = fopen(filename, "w");
            if (file == NULL) {
                fprintf(stderr, "Error opening file: %s\n", filename);
                sqlite3_finalize(stmt);
                return;
            }
            fprintf(file, "Date,Time,Source IP,Source Port,Destination IP,Destination Port,Protocol,Packet Length\n");
            break;
        case 2:
            strcpy(filename, "network_data.json");
            file = fopen(filename, "w");
            if (file == NULL) {
                fprintf(stderr, "Error opening file: %s\n", filename);
                sqlite3_finalize(stmt);
                return;
            }
            fprintf(file, "[\n");
            break;
        case 3:
            strcpy(filename, "network_data.txt");
            file = fopen(filename, "w");
            if (file == NULL) {
                fprintf(stderr, "Error opening file: %s\n", filename);
                sqlite3_finalize(stmt);
                return;
            }
            break;
        default:
            fprintf(stderr, "Invalid export format choice.\n");
            sqlite3_finalize(stmt);
            return;
    }

    int row_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *date = (const char *)sqlite3_column_text(stmt, 0);
        const char *time = (const char *)sqlite3_column_text(stmt, 1);
        const char *src_ip = (const char *)sqlite3_column_text(stmt, 2);
        int src_port = sqlite3_column_int(stmt, 3);
        const char *dst_ip = (const char *)sqlite3_column_text(stmt, 4);
        int dst_port = sqlite3_column_int(stmt, 5);
        const char *protocol = (const char *)sqlite3_column_text(stmt, 6);
        int packet_length = sqlite3_column_int(stmt, 7);

        switch (format_choice) {
            case 1:
                fprintf(file, "%s,%s,%s,%d,%s,%d,%s,%d\n", date, time, src_ip, src_port, dst_ip, dst_port, protocol, packet_length);
                break;
            case 2:
                if (row_count > 0) {
                    fprintf(file, ",\n");
                }
                fprintf(file, "  {\n");
                fprintf(file, "    \"date\": \"%s\",\n", date);
                fprintf(file, "    \"time\": \"%s\",\n", time);
                fprintf(file, "    \"src_ip\": \"%s\",\n", src_ip);
                fprintf(file, "    \"src_port\": %d,\n", src_port);
                fprintf(file, "    \"dst_ip\": \"%s\",\n", dst_ip);
                fprintf(file, "    \"dst_port\": %d,\n", dst_port);
                fprintf(file, "    \"protocol\": \"%s\",\n", protocol);
                fprintf(file, "    \"packet_length\": %d\n", packet_length);
                fprintf(file, "  }");
                break;
            case 3:
                fprintf(file, "Date: %s\n", date);
                fprintf(file, "Time: %s\n", time);
                fprintf(file, "Source IP: %s\n", src_ip);
                fprintf(file, "Source Port: %d\n", src_port);
                fprintf(file, "Destination IP: %s\n", dst_ip);
                fprintf(file, "Destination Port: %d\n", dst_port);
                fprintf(file, "Protocol: %s\n", protocol);
                fprintf(file, "Packet Length: %d\n\n", packet_length);
                break;
        }

        row_count++;
    }

    if (format_choice == 2) {
        fprintf(file, "\n]\n");
    }

    fclose(file);
    sqlite3_finalize(stmt);

    printf("Database exported to %s\n", filename);
}

int main() {
        // Check if the program is running with root privileges
        if (geteuid() != 0) {
                fprintf(stderr, "This program must be run with root privileges.\n");
        return 1;
        }
    sqlite3 *db;
    if (sqlite3_open("network_data.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Error opening database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // Create the packets table if it doesn't exist
    const char *sql = "CREATE TABLE IF NOT EXISTS packets ("
                      "date TEXT,"
                      "time TEXT,"
                      "src_ip TEXT,"
                      "src_port INTEGER,"
                      "dst_ip TEXT,"
                      "dst_port INTEGER,"
                      "protocol TEXT,"
                      "packet_length INTEGER"
                      ")";
    char *err_msg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "Error creating table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    // Create indexes on the packets table
    const char *index_sql[] = {
        "CREATE INDEX IF NOT EXISTS idx_date ON packets (date)",
        "CREATE INDEX IF NOT EXISTS idx_src_ip ON packets (src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets (dst_ip)",
        "CREATE INDEX IF NOT EXISTS idx_protocol ON packets (protocol)"
    };
    for (int i = 0; i < sizeof(index_sql) / sizeof(index_sql[0]); i++) {
        if (sqlite3_exec(db, index_sql[i], NULL, NULL, &err_msg) != SQLITE_OK) {
            fprintf(stderr, "Error creating index: %s\n", err_msg);
            sqlite3_free(err_msg);
            sqlite3_close(db);
            return 1;
        }
    }

    int choice;
    do {
        clear_screen();
        printf("Menu:\n");
        printf("1. Collect network data\n");
        printf("2. View the database\n");
        printf("3. Clear the database\n");
        printf("4. Export the database\n");
        printf("5. Exit\n");
        printf("Enter your choice: ");
        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "Invalid input. Please enter a valid number.\n");
            clear_input_buffer();
            continue;
        }

        switch (choice) {
            case 1:
                collect_network_data(db);
                break;
            case 2:
                view_database(db);
                printf("Press Enter to continue...");
                clear_input_buffer();
                break;
            case 3:
                clear_database(db);
                printf("Press Enter to continue...");
                clear_input_buffer();
                break;
            case 4:
                export_database(db);
                printf("Press Enter to continue...");
                clear_input_buffer();
                break;
            case 5:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice.\n");
                printf("Press Enter to continue...");
                clear_input_buffer();
        }
    } while (choice != 5);

    sqlite3_close(db);
    return 0;
}
