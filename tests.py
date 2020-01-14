import solution
from random import randint
import csv
def sanity_test():
    b="inbound,udp,53,192.168.1.1-192.168.2.5"
    a = "outbound,tcp,10000-20000,192.168.10.11"
    fw = solution.Firewall("test.csv")
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) #T
    print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))#T
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))#F
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))#F
    print("\n")
    print(fw.accept_packet("inbound", "udp", 53, "192.168.1.1")) #T
    print(fw.accept_packet("inbound", "udp", 53, "192.167.2.1"))  #F
    print(fw.accept_packet("inbound", "udp", 53, "192.169.3.4")) #F
    print(fw.accept_packet("inbound", "udp", 54, "192.168.2.3")) #F
    print(fw.accept_packet("inbound", "udp", 53, "192.168.1.166"))  # T
    print("\n")
    print(fw.accept_packet("outbound", "tcp", 9999, "192.168.10.11")) #F
    print(fw.accept_packet("outbound", "tcp", 10000, "192.168.10.11")) #T
    print(fw.accept_packet("outbound", "tcp", 20000, "192.168.10.11"))  # T
    print(fw.accept_packet("outbound", "tcp", 12345, "192.168.10.11"))  # T
    print(fw.accept_packet("outbound", "tcp", 12345, "192.168.10.12"))  # F
    print(fw.accept_packet("outbound", "tcp", 12345, "191.148.1.1"))  # F

def performance_test(fw):
    print("performance test starts")
    for i in range(100):
        current_packet = []
        gen_inbound = randint(0, 1)
        if gen_inbound == 1:
            current_packet.append("inbound")
        else:
            current_packet.append("outbound")

        gen_tcp = randint(0, 1)
        if gen_tcp == 1:
            current_packet.append("tcp")
        else:
            current_packet.append("udp")
        current_packet.append(generate_port(False))
        current_packet.append(generate_ip(False))
        print(fw.accept_packet(current_packet[0], current_packet[1], current_packet[2],current_packet[3]))




    pass

def gen_rule_file():
    with open('tests_2.csv', mode="w+", newline="") as file:
        writer = csv.writer(file)
        for i in range(1000000):
            current_rule = []
            gen_inbound = randint(0,1)
            if gen_inbound ==1:
                current_rule.append("inbound")
            else:
                current_rule.append("outbound")

            gen_tcp = randint(0,1)
            if gen_tcp==1:
                current_rule.append("tcp")
            else:
                current_rule.append("udp")
            current_rule.append(generate_port(True))
            current_rule.append(generate_ip(True))
            writer.writerow(current_rule)

def generate_ip(rand_range):
        if rand_range:
            gen_range = randint(0,1)
        else:
            gen_range=1
        if gen_range==1:
            current_ip = str(randint(0,255)) + "." + str(randint(0,255)) + "."+ str(randint(0,255)) + "." + str(randint(0,255))
            return current_ip
        else:
            current_ip = tuple((randint(0,255),randint(0,255),randint(0,255),randint(0,255)))
            second_ip = tuple((randint(current_ip[0],255),randint(current_ip[1],255),randint(current_ip[2],255),randint(current_ip[3],255)))
            ip_range_string = str(current_ip[0])+ "." + str(current_ip[1]) + "."+str(current_ip[2])+ "." + str(current_ip[3])+ "-" + \
                              str(second_ip[0]) + "." + str(second_ip[1]) + "."+str(second_ip[2]) + "." + str(
                second_ip[3])
            return ip_range_string

def generate_port(rand_range):
        if rand_range:
            gen_range = randint(0, 1)
        else:
            gen_range=1
        if gen_range==1:
            current_port = randint(1,65535)
            return current_port
        else:
            current_port = randint(1,65535)
            next_port = randint(current_port,65535)
            return str(current_port)+"-"+str(next_port)

#gen_rule_file()
fw = solution.Firewall("tests_2.csv")
performance_test(fw)