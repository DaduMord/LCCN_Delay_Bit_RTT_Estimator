import pyshark
import time
import os

class conn_info:
    """
    A class to hold all relevant information for each QUIC connection we detect
    Field:
        - : holds current spin bit of the connection
        - rtt: holds current RTT estimation
        - delay_ts: timestamp of the last packet we detected with a delay bit set to 1.
                    we call each packet that switches the spin bit an "edge".
        - rtt_measurements: a list that holds all the rtt measurements that were
                    made for this connection and their timestamps (in tuple form).
    """

    # initialize a new conn_info class. default for rtt field is None
    def __init__(self, edge_ts, rtt=None):
        self.rtt = rtt
        self.delay_ts = edge_ts
        self.rtt_measurements = []

    # update the rtt estimation and connection fields if necessary
    def new_measurement(self, curr_ts):
        latest_rtt = curr_ts - self.delay_ts # calculate the time difference from last delay bit
        self.rtt = self.calc_rtt(latest_rtt) # update rtt
        self.rtt_measurements.append((latest_rtt, curr_ts)) # insert measurement to measurements array
        self.delay_ts = curr_ts # update last delay bit timestamp
    
    # calculate a new rtt with the moving average algorithm
    def calc_rtt(self, new_rtt):
        if self.rtt is None: # if we don't have an estimation yet, use the last measurement as the estimation
            return new_rtt
        alpha = 7 / 8
        return alpha * self.rtt + (1 - alpha) * new_rtt 

    # override the default cast to string
    def __str__(self):
        last_edge_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.delay_ts))
        if self.rtt is None:
            res = "RTT: Not Yet Measured\n"
        else:
            res = "RTT: " + ("%.3f ms\n" % (self.rtt * 1000))
        res += "Last Edge Timestamp: " + last_edge_ts + "\n"
        return res
    
    # convert measurements array to string for printing purposes
    def measurements_tostr(self, measurements):
        if len(measurements) == 0:
            return "No Measurements"
        res = ""
        for i, measurement in enumerate(measurements):
            timestamp = measurement[1]
            timestamp_ms = timestamp % 1
            timestamp_ms = str(timestamp_ms)[2:8]
            rtt = "%.3f ms" % (measurement[0] * 1000)
            res += "%3s: %8s :: %s.%s\n" % (str(i), rtt, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)), timestamp_ms)
        return res


# print the dictionary nicely to the default output and log file
def print_conns(dict, log=None, print_separate_files=False, timestamp=None):
    """
    Expects a dictionary of type Connection ID : conn_info
    if log is not None, records the connections to log file
    if print_separate_files is True, creates a separate file for each connection and specify all RTT measurements.
    """

    for key, value in dict.items():
        print("Connection ID:", key)
        print(value, end="\n")

        if log is not None:
            log.write("Connection ID: " + str(key) + "\n" + str(value) + "\n")
        if print_separate_files:
            conn_log = ".\\QRED\\logs\\" + timestamp.replace(":", ".") + " ID " + str(key).replace(":", "") + ".txt"
            with open(conn_log, "w+") as file:
                file.write("Connection ID: " + str(key) + "\n" + str(value) + "\n" + "RTT Measurements:\n")

                measurements_str = value.measurements_tostr(value.rtt_measurements)
                file.write(measurements_str)

                file.close()

# print final message to default output and log file
def print_finish(log=None):
    print("Stopping Estimator")

    if log is not None:
        log.write("Stopping Estimator\n")

def process_header(packet, quic_header, connections_dict):
    # Extract values from quic header  
 
    # curr_delay = TODO: extract delay bit
    # if (curr_delay == False): # nothing to do if the delay bit is not turned on
    #     return

    curr_dcid = quic_header.get_field_value("dcid") # dcid = Destination Connection ID
    curr_ts = float(packet.sniff_timestamp)

    # need to check if the packet is initial (dcid will be unusable)
    header_form = quic_header.get_field_value("header_form")
    long_packet_type = quic_header.get_field_value("long_packet_type")

    # assert quic_header.get_field_value("spin_bit") == quic_header

    if header_form == "0": # short header
        if curr_dcid is not None:
            curr_info = connections_dict.setdefault(curr_dcid, conn_info(curr_ts)) # add connection if new
            # curr_info.new_measurement(curr_ts) # insert the new measurement to the connection's info #TODO: uncomment

if __name__ == "__main__":
    """
    dictionary's keys: connection ID
    dictionary's values: [current spinbit's value, estimated RTT, last edge timestamp, rtt measurements]
    """
    connections_dict = {}
    start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    filename = ".\\QRED\\logs\\log.txt" # change this in order to output to a different file

    if not os.path.exists(".\\QRED\\logs"): # check if logs folder exists
        os.makedirs(".\\QRED\\logs")        # create logs folder if not
        print("logs folder created at " + os.getcwd() + "\\QRED\\logs")

    log = open(filename, "a") # open log file in mode=append
    log.write("\nStarting capture on time: " + start_time + "\n")

    live_cap = pyshark.LiveCapture(display_filter="quic", include_raw=True, use_json=True)

    try:
        for packet in live_cap.sniff_continuously():
            # process_header(packet, packet.layers[-1], connections_dict) # packet.layers[-1] gets the last header of the packet
            
            # print(dir(packet.layers[-1]))
            # curr_dcid = packet.layers[-1].get_field_value("dcid")
            print(dir(packet.layers[-1].get_field_value("dcid")))
            # print(packet.layers[-1].value)
            
            # os._exit(0)

    except KeyboardInterrupt: # when stopped with Ctrl+C
        print_conns(connections_dict, log=log, print_separate_files=True, timestamp=start_time) # print the info of the connection and record it in log.txt
        print_finish(log) # print final message

    finally:
        log.close()