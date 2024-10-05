# sap2emu

## SAP2 Python Microprocessor Emulator

This project is a simple microprocessor emulator written in Python. It simulates a custom 8-bit processor architecture with unique features, such as dual register banks and memory-mapped I/O for peripheral devices like sound chips. The emulator provides an environment to execute binary programs on the simulated hardware, complete with ROM, RAM, and programmable I/O devices.

I built a virtual hardware version of this microprocessor using LogiSim - checkout [https://github.com/johnnyw66/SAP2/README.md](https://github.com/johnnyw66/SAP2/blob/main/README.md).

You can use the Python assembler (**assembler.py**) to produce the hex files that can run under this emulator.


### Features
Two Banks of Registers: The processor includes two banks of four registers each (R0, R1, R2, and R3). The 'EXX' opcode allows switching between these register banks, making it possible to handle two sets of registers efficiently.

## Processor Registers:

+ PC (Program Counter): Keeps track of the current instruction.
+ SP (Stack Pointer): Points to the current top of the stack.
+ Flags (F) Register: Tracks the status of operations, including:
+ Z (Zero): Set when the result of an operation is zero.
+ S (Sign): Set when the result is negative.
+ V (Overflow): Set when an arithmetic overflow occurs.
+ O (Odd Parity): Set when the number of set bits in the result is odd.
+ C (Carry): Set when a carry occurs in arithmetic operations.

## Memory:

+ 32 KB ROM: Contains the program code.
+ 32 KB RAM: Used for additional program code and data storage.
+ Memory-Mapped I/O: The emulator supports memory-mapped I/O for peripheral devices, such as sound chips. These peripherals can be dynamically added or omitted, providing flexibility for simulating various hardware configurations. If no I/O device is mapped to a specific address, the system defaults to returning ROM/RAM values.

## Requirements
This emulator requires Python 3.12 or higher.

## How to Run

Install Python 3.12
Make sure you have Python 3.12 installed. You can download it from the official Python website:
https://www.python.org/downloads/

## Clone the Repository
Clone this repository to your local machine using Git:

```
git clone https://github.com/johnnyw66/sap2emu.git
cd sap2emu

```
## Install Dependencies
This emulator does not have any external dependencies outside of Python 3.12 itself. If you plan to extend the project with additional features or libraries, you can set up a virtual environment:

```
python3 -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

## Run the Emulator
To run the emulator with a sample program:

```
python3 sap2emu.py ./example.hex
```

Replace **./example.hex** with the actual path to the hex file you want to load into the emulator. The emulator will start executing from address 0x0000 - so you may want to add a simple jump instruction to start at start of RAM (0x8000).

## Extending the Emulator
The design of the emulator is modular, so you can easily add support for new hardware components or extend the instruction set. Memory-mapped I/O peripherals can be registered dynamically, allowing you to experiment with different configurations, like adding more complex sound or display systems.

## Contribution
Feel free to open issues or submit pull requests for improvements, bug fixes, or feature additions.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

