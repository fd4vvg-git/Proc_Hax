import pymem
import psutil
import struct
import ctypes
import pymem.ressources.kernel32 as k32
import pymem.ressources.structure as s
import numpy as np
import math
import json
from colorama import init, Fore, Style
from tqdm import tqdm
import re

init(autoreset=True)



def printLogo():
    logo = r"""
     (    (        )                     )             ) 
     )\ ) )\ )  ( /(    (             ( /(   (      ( /( 
    (()/((()/(  )\())   )\            )\())  )\     )\())
     /(_))/(_))((_)\  (((_)          ((_)\((((_)(  ((_)\ 
    (_)) (_))    ((_) )\___           _((_))\ _ )\ __((_)
    | _ \| _ \  / _ \((/ __|         | || |(_)_\(_)\ \/ /
    |  _/|   / | (_) || (__          | __ | / _ \   >  < 
    |_|  |_|_\  \___/  \___|  _____  |_||_|/_/ \_\ /_/\_\
                             |_____|                     
    """
    print(Fore.MAGENTA + logo)
    print("\n     -Made By Fd4wg :)")
    print("\n \n")


# get and validate process name #

def getProcess(prompt="Enter process name (e.g. myApp.exe) or PID:\n> "):
    while True:
        user_input = input(prompt).strip()

        # Check if input is a PID
        if user_input.isdigit():
            pid = int(user_input)
            try:
                proc = psutil.Process(pid)
                print(Fore.GREEN + f"\n[+] Proc_Hax Hooked to process: {proc.name()} (PID: {proc.pid})")
                # Return a Pymem object
                pm = pymem.Pymem(proc.pid)
                return pm
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(Fore.RED + f"No process with PID {pid} found. Try again.\n")
                continue

        # Otherwise treat input as process name
        if not user_input.lower().endswith(".exe"):
            print(Fore.RED + "Invalid process name, must end with '.exe'.")
            continue

        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == user_input.lower():
                    print(Fore.GREEN + f"\n[+] Attached to process: {proc.info['name']} (PID: {proc.pid})")
                    pm = pymem.Pymem(proc.info['name'])
                    return pm
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        print(Fore.RED + "No such process available. Retry.\n")



                

# scan type menu #

def scanTypeMenu():
    print(Fore.CYAN + "\nSelect Scan Type (enter number):\n")
    print("1. Exact Value")
    print("2. Bigger than 'x'")
    print("3. Smaller than 'x'")
    print("4. Value between 'x,y'")
    print("5. Unknown Value")
    choice = input("\n\n> ").strip()
    return choice
    

# scan value type #

def valueTypeMenu():
    print(Fore.CYAN + "\nSelect Value Type:\n")
    print("1. Binary")
    print("2. Byte")
    print("3. 2 Bytes")
    print("4. 4 Bytes")
    print("5. 8 Bytes")
    print("6. Float")
    print("7. Double")
    print("8. String")
    print("9. All")
    choice = input("\n\n> ").strip()
    return choice

    
# next scan type #
    
def nextScanMenu():
    print(Fore.CYAN + "\nNext Scan Type:\n")
    print("1. Increased")
    print("2. Increased by 'x'")
    print("3. Decreased")
    print("4. Decreased by 'x'")
    print("5. Between 'x,y'")
    print("6. Changed")
    print("7. Unchanged")
    choice = input("\n\n> ").strip()
    return choice
    
# user action menu #
    
def userActionMenu():
    print(Fore.CYAN + "\nChoose next action:\n")
    print("1. Next Scan")
    print("2. View Address Value in Hex")
    print("3. Edit Value at Address")
    print("4. View Current Results")
    print("5. Pointer Scan Selected Address")
    print("6. Save Current Results to JSON")
    print("7. New Scan")
    print("8. Change Hooked Process")
    print("9. " + Fore.RED + "Exit PROC_HAX")
    return input("\n\n> ").strip()


# memory region enumeration #

MEM_COMMIT = getattr(s, "MEM_COMMIT", 0x1000)
PAGE_READWRITE = getattr(s, "PAGE_READWRITE", 0x04)
PAGE_READONLY = getattr(s, "PAGE_READONLY", 0x02)
PAGE_EXECUTE_READ = getattr(s, "PAGE_EXECUTE_READ", 0x20)
PAGE_EXECUTE_READWRITE = getattr(s, "PAGE_EXECUTE_READWRITE", 0x40)

def getMemoryRegions(pm):
    SYSTEM_INFO = s.SYSTEM_INFO()
    k32.GetSystemInfo(ctypes.byref(SYSTEM_INFO))
    
    regions = []
    addr = SYSTEM_INFO.lpMinimumApplicationAddress
    max_addr = SYSTEM_INFO.lpMaximumApplicationAddress

    mbi = s.MEMORY_BASIC_INFORMATION()

    while addr < max_addr:
        result = k32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            addr += 0x1000
            continue

        if mbi.State == MEM_COMMIT and mbi.Protect in (
            PAGE_READWRITE,
            PAGE_READONLY,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE
        ):
            regions.append((addr, mbi.RegionSize))
        addr += mbi.RegionSize

    return regions
    
# byte packing #

def packValue(value, value_type):
    if value_type == "1": return struct.pack("?", bool(value))
    if value_type == "2": return struct.pack("b", int(value))
    if value_type == "3": return struct.pack("h", int(value))
    if value_type == "4": return struct.pack("i", int(value))
    if value_type == "5": return struct.pack("q", int(value))
    if value_type == "6": return struct.pack("f", float(value))
    if value_type == "7": return struct.pack("d", float(value))
    if value_type == "8": return value.encode()
    raise ValueError("Invalid type")


def unpackValue(data, value_type):
    try:
        if value_type == "1": return struct.unpack("?", data)[0]
        if value_type == "2": return struct.unpack("b", data)[0]
        if value_type == "3": return struct.unpack("h", data)[0]
        if value_type == "4": return struct.unpack("i", data)[0]
        if value_type == "5": return struct.unpack("q", data)[0]
        if value_type == "6": return struct.unpack("f", data)[0]
        if value_type == "7": return struct.unpack("d", data)[0]
        if value_type == "8": return data.decode(errors="ignore")
    except:
        return None

def getTypeSize(value_type):
    return {
        "1": 1, "2": 1, "3": 2, "4": 4, "5": 8, "6": 4, "7": 8
    }.get(value_type, 1)




def paginateResults(results, page_size=10):
    # Yield pages of addresses and values from results dict. #
    addresses = list(results.keys())
    total = len(addresses)
    for start in range(0, total, page_size):
        end = min(start + page_size, total)
        yield addresses[start:end]

def displayResults(results, page_size=10):
    # Paginate and show memory addresses #
    addresses = list(results.keys())
    total = len(addresses)
    if total == 0:
        print(Fore.YELLOW + "\n[INFO] No results to display.\n")
        return

    pages = [addresses[i:i + page_size] for i in range(0, total, page_size)]
    page_num = 0

    while True:
        print(f"\n{Fore.CYAN}[INFO] Showing page {page_num + 1}/{len(pages)}")
        for i, addr in enumerate(pages[page_num]):
            global_index = page_num * page_size + i  # Global index in results
            print(f"{global_index + 1}. {hex(addr)} -> {results[addr]}")  # +1 for human-friendly index

        cmd = input("\n'n' = next page, 'p' = previous, 'q' = quit:\n> ").strip().lower()
        if cmd == 'n':
            if page_num + 1 < len(pages):
                page_num += 1
            else:
                print(Fore.YELLOW + "[INFO] Already at last page.")
        elif cmd == 'p':
            if page_num > 0:
                page_num -= 1
            else:
                print(Fore.YELLOW + "[INFO] Already at first page.")
        elif cmd == 'q':
            break
            
            if 0 <= idx < total:
                addr = addresses[idx]
                raw = pm.read_bytes(int(addr), getTypeSize(valueType))
                hex_str = " ".join(f"{b:02X}" for b in raw)
                print(f"\n{Fore.CYAN}[INFO] Address {hex(addr)} contains (Hex: {hex_str})")
            else:
                print(Fore.RED + "[ERROR] Index out of range.")
        else:
            print(Fore.YELLOW + "[INFO] Unknown command.")

            
            
def scanSummary(results):
    print(f"\n{Fore.GREEN}Scan complete. Total matches found: {len(results)}{Style.RESET_ALL}")
    if results:
        values = list(results.values())
        numeric_values = [v for v in values if isinstance(v, (int, float))]
        if numeric_values:
            print(f"Min: {min(numeric_values)}, Max: {max(numeric_values)}, Avg: {sum(numeric_values)/len(numeric_values):.2f}")


def saveResultsToJson(results, filename):
    json_data = {hex(addr): (int(val) if isinstance(val, np.integer) 
                                 else float(val) if isinstance(val, np.floating) 
                                 else val)
                     for addr, val in results.items()}    
    
    with open(filename, "w") as f:
        json.dump(json_data, f, indent=4)
    print(f"\n{Fore.CYAN}[INFO] Current results saved to {filename}{Style.RESET_ALL}")

# scan funcs including 3 scan methods #

def firstScan(pm, value, value_type, scanType):
    
    print("\nPerforming first memory scan...")

    size = getTypeSize(value_type)
    regions = getMemoryRegions(pm)
    results = {}

    # Parse scan-type-dependent values #
    x = None
    lo = None
    hi = None
    target_val = None

    if scanType == "1":  # exact #
        if value_type in ["2","3","4","5","6","7"]:
            target_val = float(value) if value_type in ["6","7"] else int(value)
        else:
            target_val = value

    elif scanType == "2":  # bigger than x #
        x = float(value)

    elif scanType == "3":  # smaller than x #
        x = float(value)

    elif scanType == "4":  # between x,y #
        lo, hi = map(float, value.split(","))

    # NumPy dtype mapping #
    dtype_map = {
        "2": np.int8,
        "3": np.int16,
        "4": np.int32,
        "5": np.int64,
        "6": np.float32,
        "7": np.float64
    }

    total_size = sum(length for base, length in regions)
    pbar = tqdm(total=total_size, desc="Scanning memory", ncols=None)

    for base, length in regions:
        CHUNK = 0x2000000  # 32MB
        for local_offset in range(0, length, CHUNK):
            chunk_size = min(CHUNK, length - local_offset)
            try:
                chunk_data = pm.read_bytes(base + local_offset, chunk_size)
            except:
                continue

            # Numeric types handled with NumPy #
            if value_type in dtype_map:
                dtype = dtype_map[value_type]
                arr = np.frombuffer(chunk_data, dtype=dtype)
                if scanType == "1":
                    matches = np.where(arr == target_val)[0]
                elif scanType == "2":
                    matches = np.where(arr > x)[0]
                elif scanType == "3":
                    matches = np.where(arr < x)[0]
                elif scanType == "4":
                    matches = np.where((arr >= lo) & (arr <= hi))[0]
                elif scanType == "5":
                    matches = np.arange(len(arr))
                for idx in matches:
                    addr = base + local_offset + idx * arr.itemsize
                    results[addr] = arr[idx]

            elif value_type == "1":  # bool
                for i in range(len(chunk_data)):
                    val = bool(chunk_data[i])
                    if scanType == "1" and val == target_val or scanType == "5":
                        results[base + local_offset + i] = val

            elif value_type == "8":  # string
                encoded_val = value.encode()
                matches = [m.start() for m in re.finditer(re.escape(encoded_val), chunk_data)]
                for idx in matches:
                    addr = base + local_offset + idx
                    results[addr] = value

            pbar.update(chunk_size)  # update progress bar


    pbar.close()
    displayResults(results)
    scanSummary(results)
    return results
    


def nextScan(pm, results, value_type, scanType):

    size = getTypeSize(value_type)
    newResults = {}

    x = None
    xy = None

    if scanType == "2":  # Increased by x #
        x = int(input("\nValue increased by:\n> ")) if value_type in ["2","3","4","5"] else float(input("\nValue increased by:\n> "))
    elif scanType == "4":  # Decreased by x #
        x = int(input("\nValue decreased by:\n> ")) if value_type in ["2","3","4","5"] else float(input("\nValue decreased by:\n> "))
    elif scanType == "5":  # Between x,y #
        xy = input("\nEnter min,max value:\n> ").split(",")
        xy = [int(v) if value_type in ["2","3","4","5"] else float(v) for v in xy]

    print("\nPerforming next memory scan...")

    for addr, oldValue in results.items():
        oldValue = int(oldValue) if value_type in ["2","3","4","5"] else float(oldValue)

        try:
            raw = pm.read_bytes(int(addr), size)
            newValue = unpackValue(raw, value_type)
            if newValue is None:
                continue
            newValue = int(newValue) if value_type in ["2","3","4","5"] else float(newValue)
        except:
            continue

        # Apply scan filters #
        if scanType == "1":  # Increased #
            if newValue > oldValue:
                newResults[addr] = newValue

        elif scanType == "2":  # Increased by x
            if value_type in ["6","7"]:  # float #
                if math.isclose(newValue, oldValue + x, rel_tol=1e-5):
                    newResults[addr] = newValue
            else:
                if newValue == oldValue + x:
                    newResults[addr] = newValue

        elif scanType == "3":  # Decreased #
            if newValue < oldValue:
                newResults[addr] = newValue

        elif scanType == "4":  # Decreased by x #
            if value_type in ["6","7"]:
                if math.isclose(newValue, oldValue - x, rel_tol=1e-5):
                    newResults[addr] = newValue
            else:
                if newValue == oldValue - x:
                    newResults[addr] = newValue

        elif scanType == "5":  # Between x,y #
            lo, hi = xy
            if lo <= newValue <= hi:
                newResults[addr] = newValue

        elif scanType == "6":  # Changed #
            if newValue != oldValue:
                newResults[addr] = newValue

        elif scanType == "7":  # Unchanged #
            if newValue == oldValue:
                newResults[addr] = newValue

    return newResults


def getPointerSize(pm):
    # detect process arcitecture #
    
    try:
        is_wow64 = ctypes.c_bool(False)
        handle = pm.process_handle
        k32.IsWow64Process(handle, ctypes.byref(is_wow64))
        
        if is_wow64.value:
            return 4
        
        return 8
     
    except:
        return 8

def pointerScanMenu(pm, results):
    
    try:
        index = int(input("\nEnter index of address to pointer scan:\n> ")) - 1
    except:
        print(Fore.RED + "[ERROR] Invalid index.")
        return
    
    addr_list = list(results.keys())
    if index <0 or index>= len(addr_list):
        print(Fore.RED + "[ERROR] Index out of range.")
        return
    
    target = addr_list[index]
    
    print("\nPointer Scan Parmameters:\n")
    max_depth = int(input("Max pointer depth (e.g., 5):\n> "))
    raw = input("\nMax offset range (default 4096):\n> ").strip()
    ptr_range = int(raw) if raw else 4096
    
    print(Fore.GREEN + f"\n[+] Starting Pointer Scan for {hex(target)}...\n")
    
    regions = getMemoryRegions(pm)
    ptr_size = getPointerSize(pm)
    print(Fore.YELLOW + f"\n[INFO] Detected pointer size: {ptr_size} bytes\n")

    
    pointer_paths = pointerScan(pm, target, regions, ptr_size, max_depth, ptr_range)
    
    print(Fore.CYAN + f"\nPointer scan complete. Found {len(pointer_paths)} point paths.")
    
    if len(pointer_paths) > 0:
        save = input("\nSave Pointer Paths to JSON?").lower()
        if save == "y":
            savePointerResults(pointer_paths, target)

def pointerScan(pm, target_addr, regions, ptr_size, max_depth, ptr_range):
    print(Fore.CYAN + "[INFO] Stage 1: Finding pointers referencing target address...")
    
    base_pointers = findPointersToAddress(pm, target_addr, regions, ptr_size)
    
    print(Fore. GREEN + f"\n[+] Found {len(base_pointers)} base pointers.\n")
    
    print(Fore.CYAN + "[INFO] Stage 2: Resolving full pointer chains...")
    
    all_paths = []
    for ptr in tqdm(base_pointers, desc="Building pointer paths"):
        paths = resolvePointerChains(pm, ptr, regions, ptr_size, max_depth -1 , ptr_range)
        for p in paths:
            all_paths.append([ptr] + p)
    return all_paths
    
# find all memory locations where *(addr) == target_addr #

def findPointersToAddress(pm, target_addr, regions, ptr_size):
    pointer_hits = []
    target_int = int(target_addr)  
    target_bytes = target_int.to_bytes(ptr_size, "little")

    
    for base, length in tqdm(regions, desc="Searching pointers"):
        CHUNK = 0x2000000
        for o in range(0, length, CHUNK):
            size = min(CHUNK, length, - o)
            try:
                data = pm.read_bytes(base + o, size)
            except:
                continue
            for i in range(0, size - ptr_size, ptr_size):
                if data[i:i+ptr_size] == target_bytes:
                    pointer_hits.append(base + o + i)
    return pointer_hits
    
# recursively build pointer chains #

def resolvePointerChains(pm, current_ptr, regions, ptr_size, depth_left, ptr_range):
    paths = []
    
    if depth_left <= 0:
        return [[]]
    
    try:
        data = pm.read_bytes(current_ptr, ptr_size)
        next_pointer_val = int.from_bytes(data, "little")
    except:
        return []
        
    pointer_candidates = []
    
    for base, length in regions:
        if base <= next_pointer_val <= base + length:
            offset = next_pointer_val - base
            if abs(offset) <= ptr_range:
                pointer_candidates.append(next_pointer_val)
                
    if not pointer_candidates:
        return [[]]
        
    for new_ptr in pointer_candidates:
        sub_paths = resolvePointerChains(pm, new_ptr, regions, ptr_size, depth_left - 1, ptr_range)
    
    for sp in sub_paths:
        paths.append([new_ptr] + sp)
        
    return paths
    
# save pointer paths #

def savePointerResults(paths, target):
    filename = f"pointers_{hex(target)}.json".replace("0x, """)
    data = {}
    
    for i, path in enumerate(paths):
        chain_hex = [hex(x) for x in path]
        data[f"path_{i}"] = chain_hex
        
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
            
        print(Fore.GREEN + f"\n[+] Saved pointer results to {filename}")
                    

    
    
    
    
# mem edit func #


def editAddress(pm, addr, value, value_type):
    try:
        old_raw = pm.read_bytes(int(addr), getTypeSize(value_type))
        old_value = unpackValue(old_raw, value_type)
        packed = packValue(value, value_type)
        pm.write_bytes(int(addr), packed, len(packed))
        print(f"\n{Fore.GREEN}[EDIT] {hex(addr)}: {old_value} -> {value} ✅")
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Could not edit {hex(addr)}: {e}")


#======================#
#####MAIN PROCESS#######
#======================#


def main():
    
    printLogo()
    pm = getProcess()
    scannedOnce = False
    
    while True:
    
        if not scannedOnce:
            
            scanType = scanTypeMenu()
            valueType = valueTypeMenu()    
            
            if not scannedOnce and scanType == "4":
                value = input("\nEnter min,max value:\n> ")
            if not scannedOnce and scanType == "5":
                value = ""
            if not scanType == "4" and not scanType == "5":    
                value = input("\nEnter value(s):\n> ")

            results = firstScan(pm, value, valueType, scanType)
            scannedOnce = True


            
            while scannedOnce:
                 
                choice = userActionMenu()

                if choice == "1":  # Next scan #
                    scanType = nextScanMenu()
                    results = nextScan(pm, results, valueType, scanType)
                    displayResults(results)
                    scanSummary(results)

                elif choice == "2":  # Hex view #
                    try:
                        index = int(input("\nEnter address index number to view:\n> ")) - 1
                        addr_list = list(results.keys())
                        if index < 0 or index >= len(addr_list):
                            print(Fore.RED + "[ERROR] Invalid index.")
                        else:
                            addr = addr_list[index]
                            size = getTypeSize(valueType)
                            raw = pm.read_bytes(int(addr), size)
                            value = unpackValue(raw, valueType)
                            hex_str = " ".join(f"{b:02X}" for b in raw)
                            print(f"\n{Fore.CYAN}[INFO] Address {hex(addr)} contains (Hex: {hex_str})")
                    except Exception as e:
                        print(Fore.RED + f"[ERROR] Could not read memory: {e}")


                elif choice == "3":  # Edit value #
                    try:
                        index = int(input("\nEnter address index number to edit:\n> ")) - 1
                        addr_list = list(results.keys())
                        if index < 0 or index >= len(addr_list):
                            print(Fore.RED + "[ERROR] Invalid index.")
                            continue
                        addr = addr_list[index]
                        newVal = input("\nEnter new value: ")
                        editAddress(pm, addr, newVal, valueType)
                    except Exception as e:
                        print(Fore.RED + f"[ERROR] Could not edit: {e}")

                elif choice == "4":
                    displayResults(results)
                
                elif choice == "5": # pointer scan #   
                    pointerScanMenu(pm, results)
                
                elif choice == "6":  # Save to json #
                    filename = input("\nEnter filename to save results (default: scan_results.json):\n> ").strip()
                    if not filename:
                        filename = "scan_results.json"
                    elif not filename.lower().endswith(".json"):
                        filename += ".json"
                    saveResultsToJson(results, filename)

                elif choice == "7":
                    scannedOnce = False
                    results = {}

                elif choice == "8":
                    print("\n")
                    pm = getProcess()
                    scannedOnce = False
                    results = {}
                
                elif choice == "9":
                    print(Fore.GREEN + "\nExiting.")
                    exit()


if __name__ == "__main__":
    main()
