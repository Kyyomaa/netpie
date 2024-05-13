# NetPie
Netpie is a Python-based network monitoring tool designed to capture and analyze network packets in real-time.

## Features
- Real-time Packet Sniffing
- Color-coded Outputs
- Customizable Filters
- Statistics Table

## Installation
Ensure you have Poetry, Python 3.11 or newer installed although older versions should still work. Clone the repository and set up the project using Poetry: 
- `git clone https://github.com/Kyyomaa/netpie.git`
- `cd netpie`
- `poetry install`

Alternatively install dependencies using pip:
- `git clone https://github.com/Kyyomaa/netpie.git`
- `cd netpie`
- `pip install -r requirements.txt`

## Usage
Run NetPie from the command line:
- `poetry run python netpie.py`
Or:
- `python netpie.py`

Optional arguments to filter the traffic:

- -p, --protocols [tcp|udp|icmp] - Filter by protocol types.  
- -d, --direction [in|out] - Filter by packet direction relative to the host machine.  
- -i, --ip [IP address] - Filter by specific IP address.  
- -t, --port [port number] - Filter by specific port number.  

## License
This project is licensed under the MIT License - see the LICENSE file for details.
