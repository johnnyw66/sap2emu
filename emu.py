from enum import Enum

class Flag(Enum):
    Z = 0x01  # Zero flag (bit 0)
    S = 0x02  # Sign flag (bit 1)
    O = 0x04  # Odd parity flag (bit 2)
    V = 0x08  # Overflow flag (bit 3)
    C = 0x10  # Carry flag (bit 4)

class Operation(Enum):
    ADD = 0
    SUB = 1
    LOGICAL = 2
    SHIFT_RIGHT = 3
    SHIFT_LEFT = 4

class Processor:
    def __init__(self):
        # Two banks of 4 general-purpose registers: R0, R1, R2, R3
        self.register_banks = {
            0: {'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0},  # Bank 0
            1: {'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0}   # Bank 1
        }
        self.current_bank = 0  # Start with bank 0

        # Special registers
        self.registers = {
            'PC': 0,   # Program Counter
            'SP': 0x7FFF,  # Stack Pointer (pointing to top of RAM)
            'F': 0     # Flags register
        }

        # Memory layout: 32 KB ROM (0x0000 - 0x7FFF) and 32 KB RAM (0x8000 - 0xFFFF)
        self.memory = [0] * (32 * 1024) * 2  # 64 KB total memory
        
        # Load some example ROM code into the first 32KB of memory (ROM)
        # You could expand this with real code later on
        self.rom_loaded = False

    def set_flag(self, flag: Flag, value: bool):
        """Set or clear a flag in the Flags register."""
        if value:
            self.registers['F'] |= flag.value  # Set the flag
        else:
            self.registers['F'] &= ~flag.value  # Clear the flag

    def check_flags(self, result, operand=None, operation:Operation=None):
        """Check and set the appropriate flags based on the result."""
        # Z (Zero) Flag: Set if result is zero
        self.set_flag(Flag.Z, result == 0)

        # S (Sign) Flag: Set if the most significant bit is set (sign bit for signed numbers)
        self.set_flag(Flag.S, (result & 0x80) != 0)

        # O (Odd Parity) Flag: Set if the number of 1's in the result is odd
        self.set_flag(Flag.O, bin(result).count('1') % 2 == 1)

        # C (Carry) Flag: Set if there was a carry/borrow in the operation
        if operation in [Operation.ADD, Operation.SUB] and operand is not None:
            if operation == Operation.ADD:
                carry_out = result > 0xFF  # Carry occurs if result is greater than 8 bits
            elif operation == Operation.SUB:
                carry_out = result < 0     # Borrow occurs if result is negative
            self.set_flag(Flag.C, carry_out)

        if operation == Operation.ADD and operand is not None:
            # V (Overflow) Flag: Set for signed overflow in addition
            result_sign = (result & 0x80) != 0
            operand_sign = (operand & 0x80) != 0
            self.set_flag(Flag.V, result_sign != operand_sign)


    def reset(self):
        """Reset all registers and memory."""
        print("Reset all registers and memory.")
        self.current_bank = 0
        self.register_banks = {
            0: {'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0},
            1: {'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0}
        }
        self.registers['PC'] = 0
        self.registers['SP'] = 0x7FFF
        self.registers['F'] = 0

        if not self.rom_loaded:
            # Example ROM code loaded into memory (for demo purposes)
            self.load_rom([0x01, 0x03, 0xFF, 0x00])
            self.rom_loaded = True

    def _map_regnum_to_key(sel,reg):
        return f"R{reg}"

    def set_pc(self, _16bitvalue):
        self.registers['PC'] = _16bitvalue

    def set_sp(self, _16bitvalue):
        self.registers['SP'] = _16bitvalue

    def set_reg(self, reg, _8bitvalue):
        self.register_banks[self.current_bank][self._map_regnum_to_key(reg)] = _8bitvalue

    def get_reg(self, reg):
        return self.register_banks[self.current_bank][self._map_regnum_to_key(reg)]
        
    def load_rom(self, data):
        print("load rom", data)
        """Load ROM data (up to 32KB) into the ROM area."""
        self.memory[:len(data)] = data[:32 * 1024]
        self.rom_loaded = True

    def inc_pc(self):
        self.registers['PC'] += 1  # Increment PC to point to the next instruction
        self.registers['PC'] &= 0xffff

    def inc_sp(self):
        self.registers['SP'] += 1
        self.registers['SP'] &= 0xffff


    def dec_sp(self):
        self.registers['SP'] -= 1  
        self.registers['SP'] &= 0xffff

    def fetch(self):
        """Fetch the next opcode from memory (ROM or RAM)."""
        pc = self.registers['PC']
        opcode = self.memory[pc]
        self.inc_pc()
        return opcode

    def operand_8bit(self):
        pc = self.registers['PC']
        operand = self.memory[pc]
        self.inc_pc()
        return operand

    def operand_16bit(self):
        pc = self.registers['PC']
        high = self.memory[pc]
        self.inc_pc()
        low = self.memory[(pc+1) & 0xffff]
        self.inc_pc()
        return high, low

    def switch_bank(self):
        """Flip between the two banks of registers (EXX opcode)."""
        self.current_bank = 1 - self.current_bank  # Toggle between bank 0 and bank 1
        print(f"Switched to register bank {self.current_bank}")

    def flag_str(self):
        flag = self.registers['F']
        return f"Z:{flag & Flag.Z.value} S:{flag & Flag.S.value} O:{flag & Flag.O.value} V:{flag & Flag.V.value} C:{flag & Flag.C.value}"

    def reg_dump(self):
        return str(self.register_banks) + "\n" + "PC: "+hex(self.registers['PC']) + " SP: "+ hex(self.registers['SP']) + " Flags:" + self.flag_str()


opcode_map = {} # A dictionary to store the mapping of opcodes to functions
disassembly_map = {} # A dictionary to store the disassembly mnemonic for each opcode


def opcode_handler(start, end=None, mnemonic=None):
    """
    Decorator to map a range of opcodes to a function and store the mnemonic.
    :param start: The starting opcode value
    :param end: The ending opcode value (optional)
    :param mnemonic: The mnemonic string for disassembly (optional)
    """
    def add_opcode_to_map(func):
        nonlocal end
        if end is None:  # If no end is provided, it's a single opcode
            end = start
        for opcode in range(start, end + 1):
            opcode_map[opcode] = func
            if mnemonic:
                disassembly_map[opcode] = mnemonic
        return func
    return add_opcode_to_map


@opcode_handler(0x00, mnemonic="NOP") 
@opcode_handler(0x01, mnemonic="CLC")
@opcode_handler(0x02, mnemonic="SETC")
def handle_single(proc, opcode, mnemonic):
    pass

# Undocumented OPCODE 'DUMP'
@opcode_handler(0x04, mnemonic="DUMP") 
def handle_dump(proc, opcode, mnemonic):
    print(proc.reg_dump())
    

@opcode_handler(0x14, 0x17, mnemonic="LD") 
@opcode_handler(0x18, 0x1b, mnemonic="ST")
@opcode_handler(0x1c, mnemonic="MOVWI SP")
def handle_load_store(proc, opcode, mnemonic):
    high_operand, low_operand = proc.operand_16bit()
    print(f"{mnemonic}, {hex(high_operand * 256 + low_operand)}")
    if (opcode == 0x1c):
        pass
    elif (opcode > 0x17):
        # STore
        pass
    else:
        # LoadD
        pass

@opcode_handler(0x1d,mnemonic="INC SP")
@opcode_handler(0x1e,mnemonic="DEC SP")
def handle_single_stack(proc, opcode, mnemonic):
    pass


@opcode_handler(0x1f,0x20, mnemonic="PUSH")
def handle_push_reg(proc, opcode, mnemonic):
    pass

@opcode_handler(0x22,0x23, mnemonic="POP")
def handle_pop_reg(proc, opcode, mnemonic):
    pass

@opcode_handler(0x25, mnemonic="EXX")
def handle_exx(proc, opcode, mnemonic):
    proc.switch_bank()

@opcode_handler(0x28, mnemonic="MOVWI R0")
@opcode_handler(0x2a, mnemonic="MOVWI R2")
def handle_movwi(proc, opcode, mnemonic):
    reg_src = ((opcode>>1) & 3)
    high_operand, low_operand = proc.operand_16bit()
    print(f"**************handle_movwi****************** {mnemonic}, {hex(high_operand * 256 + low_operand)}")
    proc.set_reg(reg_src, high_operand)
    proc.set_reg(reg_src + 1, low_operand)


@opcode_handler(0x40, 0x43, mnemonic="MOVI")
@opcode_handler(0x44, 0x47, mnemonic="XORI")
@opcode_handler(0x50, 0x53, mnemonic="ADDI")
@opcode_handler(0x54, 0x57, mnemonic="SUBI")
@opcode_handler(0x58, 0x5b, mnemonic="ANDI")
@opcode_handler(0x5c, 0x5f, mnemonic="ORI")
def handle_1reg_18bit(proc, opcode, mnemonic):
    reg_src = (opcode & 3)
    operand = proc.operand_8bit()
    operation = (opcode>>2) - 16 
    print(f"{mnemonic} r{reg_src}, {operand} (group {operation})\n")


    if (operation == 0):
        #MOVI rx,_8bit
        proc.set_reg(reg_src, operand)

    elif (operation == 1):
        #XORI rx,_8bit
        result = proc.get_reg(reg_src) ^ operand
        proc.check_flags(result)
        proc.set_reg(reg_src, result)

    elif (operation == 4):
        result = (proc.get_reg(reg_src) + operand)
        proc.check_flags(result, operation = Operation.ADD)
        proc.set_reg(reg_src, result & 0xff)

    elif (operation == 5):
        result = proc.get_reg(reg_src) - operand
        proc.check_flags(result, operation = Operation.SUB)
        proc.set_reg(reg_src,  result & 0xff)

    elif (operation == 6):
        result = (proc.get_reg(reg_src) & operand)
        proc.check_flags(result, operation = Operation.SUB)
        proc.set_reg(reg_src, result)

    elif (operation == 7):
        result = proc.get_reg(reg_src) | operand
        proc.check_flags(result)
        proc.set_reg(reg_src, result)
    else:
        print("DO NOT KNOW HOW TO HANDLE")

@opcode_handler(0x60, 0x63, mnemonic="DJNZ")
def handle_dnjz(proc, opcode, mnemonic):
    pass

@opcode_handler(0x64, 0x6B, mnemonic="JP")  # Condition Jump
def handle_cond_jump(proc, opcode, mnemonic):
    print("Handle conditional JP")

@opcode_handler(0x6c, mnemonic="JMP")  # Condition Jump
def handle_uncond_jump(proc, opcode, mnemonic):
    print("Handle JMP")
    high_operand, low_operand = proc.operand_16bit()

    proc.set_pc(high_operand * 256 + low_operand)

@opcode_handler(0x6e, mnemonic="CALL")  # Condition Jump
def handle_call(proc, opcode, mnemonic):
    print("Handle CALL")

@opcode_handler(0x6f, mnemonic="RET")  # Condition Jump
def handle_ret(proc, opcode, mnemonic):
    print("Handle RET")


@opcode_handler(0x80,0x83, mnemonic="SHR" )
@opcode_handler(0x84,0x87, mnemonic="SHL" )
def handle_shift(proc, opcode, mnemonic):
    pass


@opcode_handler(0x10, 0x13, mnemonic="OUT")
@opcode_handler(0x88, 0x8b, mnemonic="INC")
@opcode_handler(0x8c, 0x8f, mnemonic="DEC")
def handle_1reg_operation(proc, opcode, mnemonic):
    reg_src = (opcode & 3)

    

@opcode_handler(0x90, 0x9f, mnemonic="ADD")
@opcode_handler(0xa0, 0xbf, mnemonic="ADD")
@opcode_handler(0xb0, 0xaf, mnemonic="SUB")
@opcode_handler(0xc0, 0xcf, mnemonic="AND")
@opcode_handler(0xd0, 0xdf, mnemonic="OR")
@opcode_handler(0xe0, 0xef, mnemonic="XOR")
def handle_2reg_operations(proc, opcode, mnemonic):
    operation = opcode>>4
    reg_dest = (opcode>>2) & 3
    reg_src = (opcode & 3)
    print(f"Handle operation= {operation} {mnemonic}, r{reg_dest}, r{reg_src}")



@opcode_handler(0xff, mnemonic="HLT")
def handle_halt(proc, opcode, mnemonic):
    print(proc.reg_dump())
    while True:
        pass


# Simulator core: dispatch based on opcode
def execute_opcode(proc, opcode):
    handler = opcode_map.get(opcode)
    mnemonic = disassembly_map.get(opcode)
    if handler:
        print("DISASSEMBLER", disassemble_opcode(opcode))
        handler(proc, opcode, mnemonic)
    else:
        print(f"Unhandled opcode: {hex(opcode)}")


def execute_proc(proc):
    opcode = proc.fetch()
    execute_opcode(proc, opcode)

# Disassembler function: get mnemonic for an opcode
def disassemble_opcode(opcode):
    return disassembly_map.get(opcode, f"Unknown opcode: {hex(opcode)}")


cpu = Processor()

# Example program: [MOVI R1,0xa, MOV R0, R1; INC R1; EXX; MOVI R1, 0x2; MOV R0, R1; INC R1; EXX]
program = [
0x28, 0x80,0xFA,
0xff,
0x40, 0x10,
0x41, 0x11,
0x42, 0x12,
0x43, 0x13,

0x44, 0x10,
0x45, 0x11,
0x46, 0x12,
0x47, 0x13,

0x50, 0x10,
0x51, 0x11,
0x52, 0x12,
0x53, 0x13,

0x54, 0x10,
0x55, 0x11,
0x56, 0x12,
0x57, 0x13,

0x58, 0x10,
0x59, 0x11,
0x5a, 0x12,
0x5b, 0x13,

0x5c, 0x10,
0x5d, 0x11,
0x5e, 0x12,
0x5f, 0x13,

0x25,   #EXX
0x40, 0x12, # MOVI R0,18
0x58, 0x02, # ADDI R0,2

0xff]  # Opcodes to be executed
cpu.load_rom(program)

# Simulate execution of the program
cpu.reset()
while cpu.registers['PC'] < len(program):
    execute_proc(cpu)

# Disassemble the program
for i, byte in enumerate(program):
    print(f"{i:02X}: {disassemble_opcode(byte)}")


