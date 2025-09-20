import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
import threading


stop_scan_flag = False
suspicious_files = []

RANSOMWARE_EXTENSIONS = [
    ".crypto", ".wannacry", ".locky", ".cryptolocker", ".petya", ".badrabbit",
    ".notpetya", ".nopetya", ".ryuk", ".djvu", ".phobos", ".dharma", ".cont",
    ".nephilim", ".avaddon", ".makop", ".ransomexx", ".egregor", ".hellokitty"
]

def detect_files(directory):
    global stop_scan_flag
    ransomware_files = []

    for root, dirs, files in os.walk(directory):
        if stop_scan_flag:
            break
        for file_name in files:
            if stop_scan_flag:
                break
            file_path = os.path.join(root, file_name)


            if file_path.lower().endswith(tuple(ext.lower() for ext in RANSOMWARE_EXTENSIONS)):
                ransomware_files.append(file_path)

    return ransomware_files


def recover_file(file_path):
    try:
        original_file_path = file_path.rstrip('.crypto')
        shutil.copy(file_path, original_file_path)
        os.remove(file_path)
        return True
    except Exception as e:
        print(f"Failed to recover file '{file_path}': {e}")
        return False


def start_scan():
    global suspicious_files, stop_scan_flag
    stop_scan_flag = False
    directory = directory_var.get()

    if not directory:
        messagebox.showwarning("Directory Not Selected", "Please select a directory to scan.")
        return

    scan_button.config(state="disabled")
    stop_button.config(state="normal")
    result_label.config(text="Scanning in progress...", fg="blue")

    def perform_scan():
        global suspicious_files
        suspicious_files = detect_files(directory)
        display_results()

    threading.Thread(target=perform_scan).start()

def stop_scan():
    global stop_scan_flag
    stop_scan_flag = True
    scan_button.config(state="normal")
    stop_button.config(state="disabled")
    result_label.config(text="Scan stopped.", fg="red")

def display_results():
    if suspicious_files:
        result_text = "\n".join(suspicious_files)
        result_label.config(text=f"Ransomware-affected files:\n{result_text}", fg="red")
        recovery_isolation_frame.pack(pady=20)
    else:
        result_label.config(text="No ransomware-affected files detected.", fg="green")
        recovery_isolation_frame.pack_forget()

    scan_button.config(state="normal")
    stop_button.config(state="disabled")


def start_recovery():
    if not suspicious_files:
        messagebox.showinfo("No Suspicious Files", "No files to recover.")
        return

    def perform_recovery():
        successful, failed = 0, 0
        for file in suspicious_files:
            if recover_file(file):
                successful += 1
            else:
                failed += 1
        result_label.config(text=f"Recovery completed: {successful} recovered, {failed} failed.", fg="green")

    threading.Thread(target=perform_recovery).start()

def start_isolation():
    if not suspicious_files:
        messagebox.showinfo("No Suspicious Files", "No files to isolate.")
        return

    def perform_isolation():
        isolation_dir = filedialog.askdirectory(title="Select Isolation Directory")
        if not isolation_dir:
            return
        for file in suspicious_files:
            try:
                shutil.move(file, os.path.join(isolation_dir, os.path.basename(file)))
            except Exception as e:
                print(f"Could not isolate file '{file}': {e}")
        result_label.config(text="Files successfully isolated.", fg="blue")

    threading.Thread(target=perform_isolation).start()


root = tk.Tk()
root.title("Ransomware Detection and Isolation")
root.geometry("700x500")
root.config(bg="white")

directory_var = tk.StringVar()

title_label = tk.Label(
    root,
    text="Ransomware Detection, Recovery, and Isolation ",
    font=("Helvetica", 16, "bold"),
    bg="white",
    fg="Red"
)
title_label.pack(pady=20)


directory_frame = tk.Frame(root, bg="white")
directory_frame.pack(pady=20)

directory_label = tk.Label(directory_frame, text="Select Directory:", bg="white", font=("Helvetica", 12))
directory_label.pack(side="left", padx=5)

directory_entry = tk.Entry(directory_frame, textvariable=directory_var, width=50)
directory_entry.pack(side="left", padx=5)

browse_button = tk.Button(directory_frame, text="Browse", command=lambda: directory_var.set(filedialog.askdirectory()))
browse_button.pack(side="left", padx=5)

button_frame = tk.Frame(root, bg="white")
button_frame.pack(pady=10)

scan_button = tk.Button(button_frame, text="Start Scan", bg="green", fg="white", command=start_scan)
scan_button.pack(side="left", padx=20)

stop_button = tk.Button(button_frame, text="Stop Scan", bg="red", fg="white", state="disabled", command=stop_scan)
stop_button.pack(side="right", padx=20)


result_label = tk.Label(root, text="", font=("Helvetica", 12), bg="white", wraplength=600, justify="center")
result_label.pack(pady=10)


recovery_isolation_frame = tk.Frame(root, bg="white")
recovery_isolation_frame.pack(pady=10)
recovery_isolation_frame.pack_forget()

recovery_button = tk.Button(recovery_isolation_frame, text="Recover Files", bg="yellow", fg="black", command=start_recovery)
recovery_button.pack(side="left", padx=20)

isolation_button = tk.Button(recovery_isolation_frame, text="Isolate Files", bg="yellow", fg="black", command=start_isolation)
isolation_button.pack(side="right", padx=20)

root.mainloop()
