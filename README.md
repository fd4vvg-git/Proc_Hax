<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/7ea0d7b9-7417-42e9-bf23-3e23be91137d" />






I started playing around with cheat engine inside games, and wanted to make my own process memory editor.

DISCLAIMER:

This software is provided for lawful, ethical, and educational purposes only.
The developer does not endorse, support, or encourage any illegal, harmful, or malicious use of this software.

By using this software, you agree that you are solely responsible for complying with all applicable laws, regulations, and policies. The developer assumes no liability for any misuse, damage, loss, or legal consequences arising from the use of this software.

This software is provided “as is,” without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the developer be held liable for any claim, damages, or other liability arising from or in connection with the software or its use.

description:

PROC_HAX

PROC_HAX is a Python-based memory scanner and editor for Windows processes. It allows users to hook to running processes, scan memory for specific values, and edit them in real-time. The tool is designed for debugging, memory exploration, and experimenting with live application data. I managed to make this as efficient as possible without re-writing in c++ ;). (I will find a way to use python for everything.)

Features

Process Attachment: Attach to a process by name or PID, with validation and feedback.

Memory Scanning: Supports scans for exact values, ranges, greater/less than values, or unknown values.

Value Types: Scan and edit binary, integers (8–64 bit), floats, doubles, and strings.

Incremental Scans: Refine scan results with options like increased, decreased, changed, or unchanged values.

Memory Editing: Edit values directly in memory with immediate feedback, including hexadecimal view.

Results Management: Save scan results to JSON for later analysis.

Memory Enumeration: Automatically enumerates accessible memory regions for scanning.

Command-Line Interface: Menu-driven CLI with progress bars, colored prompts, and summaries of scan results.

Usage

Run the script and attach it to a process.

Select scan type and value type.

Perform initial scans and optionally refine results with next-scan options.

Edit memory addresses or save results as JSON.


p.s I am currently working on a massive update for this program. Hint = Pointer scanner.
