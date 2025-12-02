<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/7ea0d7b9-7417-42e9-bf23-3e23be91137d" />






I started playing around with cheat engine inside games, and wanted to make my own process memory editor.

Description:



Proc_Hax is a Python-based dynamic memory scanner and editor for Windows processes, designed to run on the CLI. It allows users to hook to running processes, scan memory for specific values, and edit them in real-time. The tool is designed for debugging, memory exploration, and experimenting with live application data. I managed to make this as efficient as possible without re-writing in c++ ;). (I will find a way to use python for everything).

Features

Process Attachment: Attach to a process by name or PID, with validation and feedback.

Memory Scanning: Supports scans for exact values, ranges, greater/less than values, or unknown values.

Value Types: Scan and edit binary, integers (8–64 bit), floats, doubles, and strings.

Incremental Scans: Refine scan results with options like increased, decreased, changed, or unchanged values.

Memory Editing: Edit values directly in memory with immediate feedback, including hexadecimal view.

Pointer Scanning: Check memory addresses that contain pointers to other addresses with precision.

Results Management: Save scan results to JSON for later analysis.

Memory Enumeration: Automatically enumerates accessible memory regions for scanning.

Command-Line Interface: Menu-driven CLI with progress bars, colored prompts, and summaries of scan results.

Usage

Run the script and attach it to a process.

Select scan type and value type.

Perform initial scans and optionally refine results with next-scan options.

Look for pointers to other memory addresses.

Edit memory addresses or save results as JSON for further analysis.

DISCLAIMER:

ProcHax is for educational use only.
