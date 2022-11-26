import pyshark
import time
import platform
import os


class ConnInfo:
    """
    A class to hold all relevant information for each QUIC connection we detect
    Field:
        - rtt: holds current RTT estimation
        - delay_ts: timestamp of the last packet we detected with a delay bit set to 1.
                    we call each packet that has a turned on delay bit by "edge".
        - rtt_measurements: a list that holds all the rtt measurements that were
                    made for this connection and their timestamps (in tuple form).
    """

    # Initialize a new conn_info class. default for rtt field is None
    def __init__(self, delay_ts: float = None, rtt: float = None):
        self.rtt = rtt
        self.delay_ts = delay_ts
        self.rtt_measurements = []
        self.T_max = 0.1  # 100 ms TODO: change this

        self.q_bit_N: int = 16
        self.q_MBT: int = self.q_bit_N // 4  # Marking Block Threshold
        self.q_curr_len: [int, int] = [0, 0]
        self.q_block_num: [int, int] = [0, 0]
        self.q_packet_count: [int, int] = [0, 0]

    def process_q_bit(self, new_q: bool) -> None:
        self.q_curr_len[new_q] += 1
        if self.q_curr_len[new_q] == self.q_MBT:  # We are in a block of new_q
            if self.q_curr_len[not new_q] != 0:  # First time we reach MBT we don't want to register the block
                self.q_block_num[not new_q] += 1
                self.q_packet_count[not new_q] += self.q_curr_len[not new_q]
                self.q_curr_len[not new_q] = 0
                event_log.write("\t\tnew q bit block confirmed\n")
        if self.q_curr_len[new_q] > self.q_bit_N:  # This would happen only under severe reordering
            # do we need to do something? might be higher, but it only means we registered the last block too soon.
            # the over-carried bit will be registered in the next block with the same q_bit.
            event_log.write("\t\tWarning: severe reordering might temper with the loss rate\n")

    def calc_loss(self) -> float:
        number_of_blocks = sum(self.q_block_num)
        number_of_packets = sum(self.q_packet_count)
        if number_of_blocks == 0:
            return -1.0
        return 1 - (number_of_packets/(number_of_blocks * self.q_bit_N))

    # Update the rtt estimation and connection fields if necessary
    def new_measurement(self, curr_ts: float):
        if self.delay_ts is None:
            self.delay_ts = curr_ts
            event_log.write("\tfirst delay encountered\n")
            return
        latest_rtt = curr_ts - self.delay_ts  # calculate the time difference from last delay bit
        if latest_rtt == 0.0:
            return
        if self.T_max is not None and latest_rtt > self.T_max:
            self.delay_ts = curr_ts  # update last delay bit timestamp
            event_log.write("\t\tnew measurement is: %.3f ms\n" % (latest_rtt * 1000))
            event_log.write("\t\tmeasurement is higher than T_max\n")
            return
        self.rtt = self.calc_rtt(latest_rtt)  # update rtt
        self.rtt_measurements.append((latest_rtt, curr_ts))  # insert measurement to measurements array
        self.delay_ts = curr_ts  # update last delay bit timestamp
        event_log.write("\t\tnew measurement is: %.3f ms\n" % (latest_rtt * 1000))
        event_log.write("\t\tnew RTT estimation is: %.3f ms\n" % (self.rtt * 1000))

    # Calculate a new rtt with the moving average algorithm
    def calc_rtt(self, new_rtt: float) -> float:
        if self.rtt is None:  # if we don't have an estimation yet, use the last measurement as the estimation
            return new_rtt
        alpha = 7 / 8
        return alpha * self.rtt + (1 - alpha) * new_rtt

    # Override the default cast to string
    def __str__(self):
        last_edge_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.delay_ts))
        if self.rtt is None:
            res = "RTT: Not Yet Measured\n"
        else:
            res = "RTT: " + ("%.3f ms\n" % (self.rtt * 1000))
        res += "Last Delay Timestamp: " + last_edge_ts + "\n"
        
        raw_loss_rate = self.calc_loss()
        if raw_loss_rate == -1.0:
            res += "Loss Rate (Q bit calculated): Not Yet Measured\n"
        else:
            res += "Loss Rate (Q bit calculated): " + str(raw_loss_rate * 100) + "%\n"
        return res

    # Convert measurements array to string for printing purposes
    def measurements_tostr(self) -> str:
        measurements = self.rtt_measurements
        if len(measurements) == 0:
            return "No Measurements"
        res = ""
        for i, measurement in enumerate(measurements):
            timestamp = measurement[1]
            timestamp_ms = str(timestamp % 1)[2:8]
            rtt = "%.3f ms" % (measurement[0] * 1000)
            res += "%3s: %8s :: %s.%s\n" % (str(i), rtt, time.strftime('%Y-%m-%d %H:%M:%S',
                                                                       time.localtime(timestamp)), timestamp_ms)
        return res


# Print the dictionary nicely to the default output and log file
def print_conns(conn_dict: dict, logs_folder, log_file=None, print_separate_files=False, timestamp=None):
    """
    Expects a dictionary of type Connection ID : conn_info
    if log is not None, records the connections to log file
    if print_separate_files is True, creates a separate file for each connection and specify all RTT measurements.
    """

    for key, value in conn_dict.items():
        print("Connection ID:", key)
        print(value, end="\n")

        print("Num of blocks is:", value.q_block_num)
        print("Num of packets is:", value.q_packet_count)

        if log_file is not None:
            log_file.write("Connection ID: " + str(key) + "\n" + str(value) + "\n")
        if print_separate_files:
            conn_log = logs_folder + dir_sign + timestamp.replace(":", ".") + " ID " + str(key).replace(":", "") + ".txt"
            with open(conn_log, "w+") as file:
                file.write("Connection ID: " + str(key) + "\n" + str(value) + "\n" + "RTT Measurements:\n")
                measurements_str = value.measurements_tostr()
                file.write(measurements_str)
                file.close()


# Print final message to default output and log file
def print_finish(log_file=None, event_log=None):
    print("Stopping Estimator")

    if log_file is not None:
        log_file.write("Stopping Estimator\n")
    if event_log is not None:
        event_log.write("Stopping Estimator\n")


# Process the quic layer and update the dictionary if necessary
def process_quic_layer(packet_ts, quic_layer, connections: dict, event_log):
    event_log.write("Caught quic packet at: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet_ts)) +
                    "." + str(packet_ts % 1)[2:8] + "\n")

    if quic_layer.has_field("header_form") and quic_layer.has_field("packet_type"):  # can't use dcid for initial packet
        if quic_layer.get_field_value("header_form") == "1" and quic_layer.get_field_value("packet_type") == "0":  # if initial packet
            event_log.write("\tinitial packet\n")
            return

    if quic_layer.has_field("dcid"):  # extract the dcid (Destination Connection ID)
        curr_dcid = quic_layer.get_field_value("dcid")
    elif quic_layer.has_field("short") and quic_layer.get_field_value("short").has_field("dcid"):
        curr_dcid = quic_layer.get_field_value("short").get_field_value("dcid")
    else:
        curr_dcid = None

    if curr_dcid is not None:
        event_log.write("\tdcid is: " + curr_dcid + "\n")
    else:
        event_log.write("\tdcid is: None\n")
        return

    if curr_dcid not in connections.keys():  # add connection if new
        event_log.write("\tdcid is new\n")
        connections[curr_dcid] = ConnInfo()

    if not quic_layer.has_field("short"):  # nothing to do if there isn't a short header
        event_log.write("\tlong header\n")
        return

    short_raw = quic_layer.get_field_value("short_raw")[0]  # extract the raw short information
    curr_delay_bit = get_delay_from_flags(get_flags(short_raw))  # extract the delay bit
    event_log.write("\tdelay is: " + str(curr_delay_bit) + "\n")

    if curr_delay_bit:  # nothing to do if the delay bit is not turned on
        connections[curr_dcid].new_measurement(packet_ts)  # insert the new measurement to the connection's info

    curr_q_bit = get_q_bit_from_flags(get_flags(short_raw))
    event_log.write("\tq bit is: " + str(curr_q_bit) + "\n")
    connections[curr_dcid].process_q_bit(curr_q_bit)


def process_packet(packet):
    packet_ts = float(packet.sniff_timestamp)
    for layer in packet:
        if layer.layer_name == "quic":
            process_quic_layer(packet_ts, layer, connections_dict, event_log)


# Extract the flags from the raw short header
def get_flags(short_raw: str) -> str:
    return short_raw[0:2]


# Extract a certain bit from the flags
def get_bit_from_flags(flags: str, bit_mask: int) -> bool:
    assert (len(flags) == 2)
    return bool(int(flags, 16) & bit_mask)


# Extract the delay bit from the flags
def get_delay_from_flags(flags: str) -> bool:
    assert (len(flags) == 2)
    delay_mask = 0x10
    return get_bit_from_flags(flags, delay_mask)


# Extract the delay bit from the flags
def get_q_bit_from_flags(flags: str) -> bool:
    assert (len(flags) == 2)
    q_bit_mask = 0x08
    return get_bit_from_flags(flags, q_bit_mask)


def get_logs_folder(dir_sign: str) -> str:
    if os.path.exists("." + dir_sign + "QRED.py"):  # we are running in the QRED folder context
        logs_folder = "." + dir_sign + "logs"
        if not os.path.exists(logs_folder):
            os.makedirs(logs_folder)
            print("logs folder created at " + os.getcwd() + dir_sign + "logs")
        return logs_folder

    else:  # we are running in the main folder context
        logs_folder = "." + dir_sign + "QRED" + dir_sign + "logs"
        if not os.path.exists(logs_folder):
            os.makedirs(logs_folder)
            print("logs folder created at " + os.getcwd() + dir_sign + "QRED" + dir_sign + "logs")
        return logs_folder

#
# def check_reserved_bits_on(quic_layer):
#     if not layer.has_field("short"):  # nothing to do if there isn't a short header
#         return
#
#     short_raw = quic_layer.get_field_value("short_raw")[0]  # extract the raw short information
#     flags = get_flags(short_raw)
#     first_mask = 0x10
#     first_reserved_bit = get_bit_from_flags(flags, first_mask)
#     second_mask = 0x08
#     second_reserved_bit = get_bit_from_flags(flags, second_mask)
#
#     if first_reserved_bit and second_reserved_bit:
#         print("first and second on!")
#     else:
#         print("something not right")
#         if first_reserved_bit is not True:
#             print("first off")
#         else:
#             print("second off")
#         raise Exception("This is bad!")


if __name__ == "__main__":
    sys_type = platform.system()  # need to check system type to know whether to use \ or /.
    if sys_type == "Windows":
        dir_sign = "\\"
    elif sys_type == "Linux":
        dir_sign = "/"
    else:
        raise Exception("Error: Script should be run on Windows or Linux platforms only")

    """
    dictionary's keys: Destination Connection ID
    dictionary's values: ConnInfo instance depicting relevant connection
    """
    connections_dict: dict = {}
    start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    logs_folder = get_logs_folder(dir_sign)
    filename = logs_folder + dir_sign + "log.txt"  # change this in order to output to a different file
    log = open(filename, "a+")  # open log file in mode=append
    log.write("\nStarting capture on time: " + start_time + "\n\n")
    event_log = open(logs_folder + dir_sign + "event_log.txt", mode="a+")
    event_log.write("\nStarting capture on time: " + start_time + "\n\n")

    live_cap = pyshark.LiveCapture(display_filter="quic", include_raw=True, use_json=True)

    try:
        live_cap.apply_on_packets(process_packet)

    except KeyboardInterrupt:  # when stopped with Ctrl+C
        # print the info of the connection and record it in log.txt
        print_conns(connections_dict, logs_folder=logs_folder, log_file=log, print_separate_files=True, timestamp=start_time)
        print_finish(log, event_log)  # print final message

    finally:
        log.close()
        event_log.close()
