# LCCN_Delay_Bit_RTT_Estimator

This is a repository offering a tool to analyze the RTTs of QUIC connection as a middle-box observer.

To use the estimator, run the QRED.py file either from the repository home directory or from the QRED folder within.

The tool will automatically detect QUIC connections and analyze their RTTs.

To stop the tool, send a Ctrl+C to it. Upon receiving the signal, the tool will stop and print various logs:
1. QRED\logs\log.txt is a general log which holds the summary of all connections detected.
2. QRED\logs\event_log.txt is a more specific log which specifies the information of each packet caught.
3. QRED\logs\{connection id}.txt is a log file that specifies all the RTT measurements which were made for the connection {connection id}.


## Important Notice

This tool currently runs on Windows platform only.

This tool requires tshark and pyshark as dependencies.
For tshark, we recommend to install [Wireshark](https://www.wireshark.org/download.html) as it will automatically install tshark as well.

Pyshark can be obtained using python pip.

IMPORTANT:
Pyshark was updated and deleted functionalities this tool uses.

Please install Pyshark version 0.4.5. You can do that by running:

```bash
pip install pyshark==0.4.5
```
or
```bash
pip3 install pyshark==0.4.5
```
