import csv

class Firewall(object):
    def __init__(self, path):
        self.udp_inbound_rules=[]
        self.tcp_inbound_rules = []
        self.udp_outbound_rules = []
        self.tcp_outbound_rules=[]
        with open(path) as file:
            reader = csv.reader(file)
            for row in reader:
                current_rule = []
                if "-" in row[2]:
                    current_rule.append(True) #current rule for port is a range
                    port_range = row[2].split("-")
                    current_rule.append([int(port_range[0]),int(port_range[1])])
                else:
                    current_rule.append(False)
                    current_rule.append(int(row[2]))
                if "-" in row[3]:
                    current_rule.append(True)  # current rule for ip is a range
                    ip_range = row[3].split("-")
                    current_rule.append([self.convert_ipv4(ip_range[0]),self.convert_ipv4(ip_range[1])])

                else:
                    current_rule.append(False)
                    current_rule.append(self.convert_ipv4(row[3]))
                if row[0]=="outbound":
                    if row[1] =="tcp":
                        self.tcp_outbound_rules.append(current_rule)
                    else:
                        self.udp_outbound_rules.append(current_rule)
                else:
                    if row[1] == "tcp":
                        self.tcp_inbound_rules.append(current_rule)
                    else:
                        self.udp_inbound_rules.append(current_rule)

    def convert_ipv4(self,ip_string):
        ip_numbers = ip_string.split(".")
        return tuple(int(number) for number in ip_numbers)

    def check_ip_in_range(self, ip_string, range_start,range_end):
        return range_start <= self.convert_ipv4(ip_string) <= range_end

    def check_packet_matches(self, rules, port, ip_address):
        for rule in rules:
            matches_current_rule = True
            if rule[0]:
                if not (port >= rule[1][0] and port <= rule[1][1]):
                    matches_current_rule = False
            else:
                if port != rule[1]:
                    matches_current_rule = False
            if not matches_current_rule:
                continue
            if rule[2]:
                if not self.check_ip_in_range(ip_address, rule[3][0], rule[3][1]):
                    matches_current_rule = False
            else:
                if self.convert_ipv4(ip_address) != rule[3]:
                    matches_current_rule = False
            if matches_current_rule:
                return True
        return False

    def accept_packet(self, direction, protocol, port, ip_address):
        if direction =="outbound":
            if protocol=="tcp":
                return self.check_packet_matches(self.tcp_outbound_rules, port, ip_address)
            else:
                return self.check_packet_matches(self.udp_outbound_rules, port, ip_address)
        else:
            if protocol=="tcp":
                return self.check_packet_matches(self.tcp_inbound_rules, port, ip_address)
            else:
                return self.check_packet_matches(self.udp_inbound_rules, port, ip_address)


