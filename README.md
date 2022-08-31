# LCCN_Delay_Bit_RTT_Estimator

To use the estimator, run the QRED.py file either from the repository home directory or from the QRED folder within.

The tool will automatically detect QUIC connections and analyze their RTTs.

To stop the tool, send a Ctrl+C to it. Upon receiving the signal, the tool will stop and print various logs:
1. QRED\logs\log.txt is a general log which holds the summary of all connections detected.
2. QRED\logs\event_log.txt is a more specific log which specifies the information of each packet caught.
3. QRED\logs\{connection id}.txt is a log file that specifies all the RTT measurements which were made for the connection {connection id}.