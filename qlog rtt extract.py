

qlogname = "C:\\Technion\\CommunicationProject\\LCCN_Delay_Bit_RTT_Estimator\\Estimation_Records\\100KB regular\\client_qlog.qlog"


def parse_int(string):
    res = ""
    for char in string:
        if not char.isdigit() and not char == ".":
            break
        res += char
    return pad_rtt_with_0(res, 19)


def extract_timestamp(string):
    return str(float(parse_int(string.split("\"time\": ")[1])[8:])/1000)


def pad_rtt_with_0(float_str: str, target_length: int) -> str:
    if len(float_str) < target_length:
        return float_str + "0" * (target_length - len(float_str))
    else:
        return float_str


if __name__ == "__main__":
    with open(qlogname, "r") as file:
        for line in file.readlines():
            split = line.split("\"latest_rtt\": ")

    last_rtt = ""
    for element in split[1:]:
        rtt = parse_int(element)
        timestamp = extract_timestamp(element)
        if not rtt == last_rtt:
            print(rtt, ",", timestamp)
            last_rtt = rtt


