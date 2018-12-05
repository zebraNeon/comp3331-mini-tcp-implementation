# comp3331-mini-tcp-implementation

## Introduction
This is an implementation of a subset of functions of the TCP protocol to transmit a file for both data senders and data receivers for UNSW COMP3331 18s2 assignment. It is written in Python 3.

## Features
This implementaion aims to simulate the process of TCP transmission, including three-way handshake for connection establishing and for-segment handshake for connection termination, how TCP deals with transmission errors like segment lost or segment corrpution, and sending window and receiving buffer as well. Since both the sender and the receiver are running at the local network, a extra package loss and delay (PLD) module is implemented to simulate network problems.

This implementation also includes log for both the sender and the receiver, which carefully logged all the events happened during the transmission.

## How to run?
For `sender.py`, it takes 14 arguments in the format of
```
python3 sender.py $receiver_host_ip $receiver_port $file $MWS $MSS $gamma $pDrop $pDuplicate $pCorrupt $pOrder $maxOrder $pDelay $maxDelay $seed
```
Of these, arguments starting from `$pDrop` is for PLD module. The following table is for the meaning of each of these arguments.

| Argument Name | Meaning |
| -------------- | -----|
| receiver_host_ip | the host ip of the machine that the receiver is running |
| receiver_port    | the port that the receiver is listening to |
| file      | the name of file to be transmitted |
| MWS | sender's maximum (sending) window size (in bytes) |
| MSS | maximum (data) segment size (in bytes) for each package |
| gamma | a relative number for how long the timeout should be for each roundtrip of transmission |
| pDrop | the probability of package droping |
| pDuplicate | the probability of package duplicatedly sent |
| pCorrupt | the probability of package being corrupted (has bit error) |
| pOrder | the probability of package being reordered (sent after sending of several other packages) |
| maxOrder | the maximum number of package being sent before the reordered package is sent |
| pDelay | the probability of package being delayed |
| maxDelay | the maximum delaying time allowed |
| seed | seed for random number generator |

For `receiver.py`, it takes 2 arguments in the format of
```
python3 receiver.py $receiver_port $file
```
Of which the first argument is the port number that receiver listens to and the second is the file name of the received file.

The receiver should be firstly started then a file can be transmitted with the sender.
For example, we may first run `python3 receiver.py 2000 test1-dup.pdf` then run `python3 sender.py 127.0.0.1 2000 test1.pdf 500 50 2 0.5 0 0 0 0 0.2 1000 300` in another shell.
