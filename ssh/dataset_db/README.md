# Datasets
The collection was made on single server with multiple benign accesses from human users and also from robots (zabbix). The vast majority of captured login attempts is malicious.

### Features


| *Name*                       |  *Database Type*     |  *Description*                                              |
--- | --- | ---
| *BRUTEFORCE*               |	*INTEGER*   | *LABEL (1 - true, 0 false)*                                   |
| time_start                   |	real          | Linux Timestamp                                                 |
| time_end                     |	real          | Linux Timestamp                                                 |
| dt_time_start                |	text          | human readable                                                  |
| dt_time_end                  |	text          | human readable                                                  |
| idp_in                       |	integer       | Initial data packet IN                                          |
| idp_out                      |	integer       | Initial data packet OUT                                         |
| sa                           |	text          | Source Address                                                 |
| da                           |	text          | Destination Address                                            |
| dp                           |	integer       | Destination Port                                                |
| sp                           |	integer       | Source port                                                    |
| entropy                      |	real          | The entropy in bits per byte                                    |
| total_entropy                |	real          | Total entropy, in bytes, over all of the bytes in the flow      |
| duration                     |	integer       | In seconds                                                      |
| pr                           |	text          | Protocol number                                                 |
| fdp_len                      |	integer       | First data packet length                                        |
| ldp_len                      |	integer       | Last data packet length                                        |
| num_pkts_in                  |	integer       | The number of IN packets in bytes                              |
| num_pkts_out                 |	integer       | The number of OUT packets in bytes                              |
| num_pkts                     |	integer       | The total number of packets in bytes                            |
| bytes_in                     |	integer       |                                                                 |
| bytes_out                    |	integer       |                                                                 |
| avg_ipt                      |	real          | Average inter-packet time in flow                               |
| med_ipt                      |	integer       | Median inter-packet time in flow                                |
| var_ipt                      |	real          | Variance of inter-packet time in flow                           |
| ssh_client                   |	text          | Name of the ssh client                                          |
| avgp_len                     |	integer       | Average packet length in flow                                  |
| varp_len                     |	real          | Variance of packet length in flow                              |
| medp_len                     |	integer       | Median of packets length in flow                                |
| ssh_version                  |	text          | Version of used ssh                                             |
| ssh                          |	integer       | SSH header recognized (1- true, 0-false)                       |
| kex_algos_lenght             |	integer       | The number of key exchange algorithms provided by client       |
| encryption_algo_lenght       |	integer       | The number of encryption algorithms provided by client         |
| first_encryption_algo        |	text          | The name of first provided encryption algorithm                |
| 3des-cbc                     |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| 3des-ctr                     |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| aes128-cbc                   |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| aes128-ctr                   |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| aes128-gcm@openssh.com       |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| aes192-cbc                   |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| aes192-ctr                   |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| aes256-cbc                   |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| aes256-ctr                   |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| aes256-gcm@openssh.com       |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| arcfour                      |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| arcfour128                   |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| arcfour256                   |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| blowfish-cbc                 |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| blowfish-ctr                 |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| cast128-cbc                  |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| chacha20-poly1305@openssh.com|	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| des-cbc-ssh1                 |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| rijndael-cbc@lysator.liu.se  |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| twofish128-cbc               |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| twofish256-cbc               |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| support_other_enc            |	integer       | Support of algorithm by client. (1 - true, 0 -false)           |
| interflow_gap                |	real          | The interval between last flow initiated by same source IP address  |
| dp_6_bytes                   |	integer       | The size of 6-th datapacket in bytes.                          |
| dp_7_bytes                   |	integer       | The size of 7-th datapacket in bytes.                          |
| dp_8_bytes                   |	integer       | The size of 8-th datapacket in bytes.                          |
| dp_9_bytes                   |	integer       | The size of 9-th datapacket in bytes.                          |
| dp_10_bytes                  |	integer       | The size of 10-th datapacket in bytes.                         |
| dp_11_bytes                  |	integer       | The size of 11-th datapacket in bytes.                         |
| dp_12_bytes                  |	integer       | The size of 12-th datapacket in bytes.                         |
| dp_13_bytes                  |	integer       | The size of 13-th datapacket in bytes.                         |
| dp_15_bytes                  |	integer       | The size of 14-th datapacket in bytes.                         |
| dp_16_bytes                  |	integer       | The size of 15-th datapacket in bytes.                         |
| fin_count                    |	integer       | The number of TCP FIN flag occurred in flow.                   |
| reset_count                  |	integer       | The number of TCP RST flag occurred in flow.                   |


