#pragma once
#include <map>
static map<int, string> services = {

    // ===== File Transfer =====
    {20, "FTP-Data"},
    {21, "FTP"},
    {69, "TFTP"},
    {989, "FTPS-Data"},
    {990, "FTPS"},

    // ===== Remote Access =====
    {22, "SSH"},
    {23, "Telnet"},
    {512, "rexec"},
    {513, "rlogin"},
    {514, "rsh"},
    {3389, "RDP"},
    {5900, "VNC"},

    // ===== Mail =====
    {25, "SMTP"},
    {110, "POP3"},
    {143, "IMAP"},
    {465, "SMTPS"},
    {587, "SMTP-Submission"},
    {993, "IMAPS"},
    {995, "POP3S"},

    // ===== DNS / Network =====
    {53, "DNS"},
    {67, "DHCP-Server"},
    {68, "DHCP-Client"},
    {123, "NTP"},
    {161, "SNMP"},
    {162, "SNMP-Trap"},

    // ===== Web =====
    {80, "HTTP"},
    {443, "HTTPS"},
    {8000, "HTTP"},
    {8008, "HTTP"},
    {8080, "HTTP-Proxy"},
    {8081, "HTTP"},
    {8443, "HTTPS"},
    {8888, "HTTP"},

    // ===== Databases =====
    {1433, "Microsoft-SQL-Server"},
    {1521, "Oracle"},
    {3306, "MySQL"},
    {5432, "PostgreSQL"},
    {6379, "Redis"},
    {27017, "MongoDB"},
    {9042, "Cassandra"},
    {5984, "CouchDB"},

    // ===== Directory / Authentication =====
    {88, "Kerberos"},
    {389, "LDAP"},
    {636, "LDAPS"},
    {464, "Kerberos-Password"},
    {3268, "Global-Catalog"},
    {3269, "Global-Catalog-SSL"},

    // ===== File Sharing =====
    {111, "RPCBind"},
    {139, "NetBIOS-SSN"},
    {445, "SMB"},
    {2049, "NFS"},

    // ===== Messaging / Queue =====
    {1883, "MQTT"},
    {8883, "MQTT-TLS"},
    {5672, "AMQP"},
    {15672, "RabbitMQ-Management"},

    // ===== Proxy / Cache =====
    {1080, "SOCKS-Proxy"},
    {3128, "Squid-Proxy"},
    {8080, "HTTP-Proxy"},
    {8118, "Privoxy"},

    // ===== Monitoring =====
    {10050, "Zabbix-Agent"},
    {10051, "Zabbix-Server"},
    {9090, "Prometheus"},
    {9100, "Node-Exporter"},

    // ===== Containers / DevOps =====
    {2375, "Docker"},
    {2376, "Docker-TLS"},
    {6443, "Kubernetes-API"},

    // ===== Version Control =====
    {9418, "Git"},

    // ===== VoIP =====
    {5060, "SIP"},
    {5061, "SIP-TLS"},

    // ===== Windows =====
    {135, "MSRPC"},
    {137, "NetBIOS-NS"},
    {138, "NetBIOS-DGM"},
    {139, "NetBIOS-SSN"},
    {445, "SMB"},

    // ===== Printing =====
    {515, "LPD"},
    {631, "IPP"},

    // ===== VPN =====
    {500, "ISAKMP"},
    {1194, "OpenVPN"},
    {1701, "L2TP"},
    {1723, "PPTP"},
    {4500, "IPsec-NAT-T"},

    // ===== Proxy / Application =====
    {8000, "HTTP"},
    {8080, "HTTP-Proxy"},
    {8088, "HTTP"},
    {8888, "HTTP"},

    // ===== Elasticsearch / Search =====
    {9200, "Elasticsearch"},
    {9300, "Elasticsearch-Transport"},

    // ===== Jenkins =====
    {8080, "HTTP/Jenkins"},
    {50000, "Jenkins-Agent"},

    // ===== Java / Application Servers =====
    {1099, "Java-RMI"},
    {7001, "WebLogic"},
    {8009, "AJP"},
    {8080, "Tomcat"},
    {8443, "Tomcat-HTTPS"},

    // ===== Remote Management =====
    {5985, "WinRM-HTTP"},
    {5986, "WinRM-HTTPS"},

    // ===== Syslog =====
    {514, "Syslog"},
    {6514, "Syslog-TLS"},

    // ===== IRC =====
    {6667, "IRC"},
    {6697, "IRC-TLS"},

    // ===== XMPP =====
    {5222, "XMPP-Client"},
    {5269, "XMPP-Server"}
};
