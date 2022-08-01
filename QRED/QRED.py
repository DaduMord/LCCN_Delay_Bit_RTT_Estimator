import pyshark
import time
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
    def __init__(self, edge_ts: float, rtt: float = None):
        self.rtt = rtt
        self.delay_ts = edge_ts
        self.rtt_measurements = []

    # Update the rtt estimation and connection fields if necessary
    def new_measurement(self, curr_ts: float):
        latest_rtt = curr_ts - self.delay_ts  # calculate the time difference from last delay bit
        if latest_rtt == 0.0:
            return
        self.rtt = self.calc_rtt(latest_rtt)  # update rtt
        self.rtt_measurements.append((latest_rtt, curr_ts))  # insert measurement to measurements array
        self.delay_ts = curr_ts  # update last delay bit timestamp

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
        res += "Last Edge Timestamp: " + last_edge_ts + "\n"
        return res

    # Convert measurements array to string for printing purposes
    def measurements_tostr(self) -> str:
        measurements = self.rtt_measurements
        if len(measurements) == 0:
            return "No Measurements"
        res = ""
        for i, measurement in enumerate(measurements):
            timestamp = measurement[1]
            timestamp_ms = timestamp % 1
            timestamp_ms = str(timestamp_ms)[2:8]
            rtt = "%.3f ms" % (measurement[0] * 1000)
            res += "%3s: %8s :: %s.%s\n" % (str(i), rtt, time.strftime('%Y-%m-%d %H:%M:%S',
                                                                       time.localtime(timestamp)), timestamp_ms)
        return res


# Print the dictionary nicely to the default output and log file
def print_conns(conn_dict: dict, log_file=None, print_separate_files=False, timestamp=None):
    """
    Expects a dictionary of type Connection ID : conn_info
    if log is not None, records the connections to log file
    if print_separate_files is True, creates a separate file for each connection and specify all RTT measurements.
    """

    for key, value in conn_dict.items():
        print("Connection ID:", key)
        print(value, end="\n")

        if log_file is not None:
            log_file.write("Connection ID: " + str(key) + "\n" + str(value) + "\n")
        if print_separate_files:
            conn_log = ".\\QRED\\logs\\" + timestamp.replace(":", ".") + " ID " + str(key).replace(":", "") + ".txt"
            with open(conn_log, "w+") as file:
                file.write("Connection ID: " + str(key) + "\n" + str(value) + "\n" + "RTT Measurements:\n")

                measurements_str = value.measurements_tostr()
                file.write(measurements_str)

                file.close()


# Print final message to default output and log file
def print_finish(log_file=None):
    print("Stopping Estimator")

    if log_file is not None:
        log_file.write("Stopping Estimator\n")

# Process the quic layer and update the dictionary if necessary
def process_quic_layer(quic_packet, quic_layer, connections: dict):
    if quic_layer.has_field("dcid"):  # extract the dcid (Destination Connection ID)
        curr_dcid = quic_layer.get_field_value("dcid")
    elif quic_layer.has_field("short"):
        curr_dcid = quic_layer.get_field_value("short").get_field_value("dcid")
    else:
        curr_dcid = None
    curr_ts = float(quic_packet.sniff_timestamp)  # extract the timestamp of the packet

    if curr_dcid is not None and curr_dcid not in connections.keys():  # add connection if new
        connections[curr_dcid] = ConnInfo(curr_ts)

    if not layer.has_field("short"):  # nothing to do if there isn't a short header
        return

    short_raw = quic_layer.get_field_value("short_raw")[0]  # extract the raw short information
    curr_delay_bit = get_delay_from_flags(get_flags(short_raw))  # extract the delay bit

    if curr_delay_bit and curr_dcid is not None:  # nothing to do if the delay bit is not turned on
        connections[curr_dcid].new_measurement(curr_ts)  # insert the new measurement to the connection's info


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


if __name__ == "__main__":
    """
    dictionary's keys: Connection ID
    dictionary's values: ConnInfo instance depicting relevant connection
    """
    connections_dict: dict = {}
    start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    filename = ".\\QRED\\logs\\log.txt"  # change this in order to output to a different file

    if not os.path.exists(".\\QRED\\logs"):  # check if logs folder exists
        os.makedirs(".\\QRED\\logs")  # create logs folder if not
        print("logs folder created at " + os.getcwd() + "\\QRED\\logs")

    log = open(filename, "a")  # open log file in mode=append
    log.write("\nStarting capture on time: " + start_time + "\n\n")

    live_cap = pyshark.LiveCapture(display_filter="quic", include_raw=True, use_json=True)

    try:
        for packet in live_cap.sniff_continuously():
            for layer in packet.layers:
                if layer.layer_name == "quic":
                    process_quic_layer(packet, layer, connections_dict)

    except KeyboardInterrupt:  # when stopped with Ctrl+C
        # print the info of the connection and record it in log.txt
        print_conns(connections_dict, log_file=log, print_separate_files=True, timestamp=start_time)
        print_finish(log)  # print final message

    finally:
        log.close()
