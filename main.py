import os
import shutil
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import logging
import queue

# Configure logging to file.
logging.basicConfig(
    level=logging.INFO,
    filename="backup_app.log",
    filemode="a",
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class BackupApp:
    def __init__(self, root):
        """Initialize the backup application UI and state."""
        self.root = root
        self.root.title("Tomas Ramoska Backup App")
        self.root.geometry("600x550")  # Increased height to accommodate log panel

        # Data state
        self.source_folders = []       # List to hold source folder paths.
        self.destination_folder = ""   # Destination folder path.
        self.total_bytes = 0
        self.copied_bytes = 0
        self.cancel_backup = False     # Flag to cancel backup.
        self.error_queue = queue.Queue()  # Queue to hold error messages for UI display

        # Setup UI and track interactive widgets.
        self.setup_ui()

        # Start periodic check for error messages to update the UI.
        self.root.after(100, self.check_error_queue)

    def setup_ui(self):
        """Set up the UI elements."""
        # --- Source Folder Section ---
        src_frame = tk.LabelFrame(self.root, text="Source Folders")
        src_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.source_listbox = tk.Listbox(src_frame, height=6)
        self.source_listbox.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        scrollbar = tk.Scrollbar(src_frame, orient="vertical", command=self.source_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.source_listbox.config(yscrollcommand=scrollbar.set)

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(fill="x", padx=10)
        self.add_btn = tk.Button(btn_frame, text="Add Source Folder", command=self.add_source_folder)
        self.add_btn.pack(side="left", padx=5, pady=5)
        self.remove_btn = tk.Button(btn_frame, text="Remove Selected", command=self.remove_selected_source)
        self.remove_btn.pack(side="left", padx=5, pady=5)

        # --- Destination Folder Section ---
        dest_frame = tk.Frame(self.root)
        dest_frame.pack(fill="x", padx=10, pady=5)
        dest_label = tk.Label(dest_frame, text="Destination Folder:")
        dest_label.pack(side="left")
        self.dest_entry = tk.Entry(dest_frame, width=40)
        self.dest_entry.pack(side="left", padx=5)
        self.dest_btn = tk.Button(dest_frame, text="Browse", command=self.select_destination)
        self.dest_btn.pack(side="left", padx=5)

        # --- Progress Bar Section ---
        prog_frame = tk.Frame(self.root)
        prog_frame.pack(fill="x", padx=10, pady=5)
        self.progress_bar = ttk.Progressbar(prog_frame, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.pack(pady=5)
        self.progress_label = tk.Label(prog_frame, text="Progress: 0%")
        self.progress_label.pack()

        # --- Log Message Section ---
        log_frame = tk.LabelFrame(self.root, text="Log Messages")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_text = tk.Text(log_frame, height=8, state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        log_scrollbar = tk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scrollbar.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=log_scrollbar.set)

        # --- Control Buttons Section ---
        ctrl_frame = tk.Frame(self.root)
        ctrl_frame.pack(pady=10)
        self.start_btn = tk.Button(ctrl_frame, text="Start Backup", command=self.start_backup)
        self.start_btn.pack(side="left", padx=10)
        self.cancel_btn = tk.Button(
            ctrl_frame,
            text="Cancel Backup",
            command=self.cancel_backup_operation,
            state="disabled",
        )
        self.cancel_btn.pack(side="left", padx=10)

    def log_message(self, message, level="info"):
        """
        Log a message using the logging module and push it to the UI error queue.
        Levels: "info", "warning", "error"
        """
        if level == "info":
            logging.info(message)
        elif level == "warning":
            logging.warning(message)
        elif level == "error":
            logging.error(message)
        self.error_queue.put(f"{level.upper()}: {message}")

    def check_error_queue(self):
        """Periodically check for messages in the error queue and update the log widget."""
        try:
            while True:
                msg = self.error_queue.get_nowait()
                self.append_log(msg)
        except queue.Empty:
            pass
        self.root.after(100, self.check_error_queue)

    def append_log(self, message):
        """Append a message to the log text widget."""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def clear_log(self):
        """Clear all text from the log widget."""
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state="disabled")

    def add_source_folder(self):
        """Prompt user to select a source folder and add it to the list."""
        folder = filedialog.askdirectory(title="Select Source Folder")
        if folder and folder not in self.source_folders:
            self.source_folders.append(folder)
            self.source_listbox.insert(tk.END, folder)

    def remove_selected_source(self):
        """Remove selected source folders from the list."""
        selected_indices = self.source_listbox.curselection()
        for index in reversed(selected_indices):
            folder = self.source_listbox.get(index)
            self.source_folders.remove(folder)
            self.source_listbox.delete(index)

    def select_destination(self):
        """Prompt user to select the destination folder."""
        folder = filedialog.askdirectory(title="Select Destination Folder")
        if folder:
            self.destination_folder = folder
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, folder)

    def start_backup(self):
        """Validate selections and start the backup process."""
        if not self.source_folders:
            messagebox.showwarning("Warning", "Please add at least one source folder.")
            return
        if not self.destination_folder:
            messagebox.showwarning("Warning", "Please select a destination folder.")
            return

        # Reset cancellation flag, progress counters, and clear log.
        self.cancel_backup = False
        self.total_bytes = self.calculate_total_bytes()
        self.copied_bytes = 0
        self.progress_bar["value"] = 0
        self.progress_label.config(text="Progress: 0%")
        self.clear_log()

        # Disable UI elements during backup.
        self.disable_ui()
        self.cancel_btn.config(state="normal", text="Cancel Backup")

        # Run backup in a separate thread to keep UI responsive.
        threading.Thread(target=self.backup_files, daemon=True).start()

    def calculate_total_bytes(self):
        """Calculate the total number of bytes in all selected source folders."""
        total = 0
        for folder in self.source_folders:
            for root, _, files in os.walk(folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        try:
                            total += os.path.getsize(file_path)
                        except OSError as e:
                            self.log_message(
                                f"Error getting size for {file_path}: {e}",
                                level="error",
                            )
        return total

    def copy_file(self, src_file, dest_file):
        """
        Copy a single file from src_file to dest_file.
        Returns the size of the file copied, or 0 if an error occurred.
        """
        try:
            shutil.copy2(src_file, dest_file)
            return os.path.getsize(src_file)
        except FileNotFoundError as e:
            self.log_message(f"File not found: {src_file} - {e}", level="error")
        except PermissionError as e:
            self.log_message(f"Permission error copying {src_file}: {e}", level="error")
        except OSError as e:
            self.log_message(f"OS error copying {src_file}: {e}", level="error")
        except Exception as e:
            self.log_message(f"Unexpected error copying {src_file}: {e}", level="error")
        return 0

    def backup_files(self):
        """Perform the backup of files from source folders to the destination folder."""
        for src in self.source_folders:
            if self.cancel_backup:
                self.root.after(0, self.backup_canceled)
                return
            folder_name = os.path.basename(src.rstrip(os.sep))
            dest_folder = os.path.join(self.destination_folder, folder_name)
            for root_dir, _, files in os.walk(src):
                if self.cancel_backup:
                    self.root.after(0, self.backup_canceled)
                    return
                relative_path = os.path.relpath(root_dir, src)
                current_dest = os.path.join(dest_folder, relative_path)
                try:
                    os.makedirs(current_dest, exist_ok=True)
                except OSError as e:
                    self.log_message(
                        f"Could not create directory {current_dest}: {e}",
                        level="error",
                    )
                    continue
                for file in files:
                    if self.cancel_backup:
                        self.root.after(0, self.backup_canceled)
                        return
                    src_file = os.path.join(root_dir, file)
                    dest_file = os.path.join(current_dest, file)
                    file_size = self.copy_file(src_file, dest_file)
                    self.copied_bytes += file_size
                    self.update_progress()
        self.root.after(0, self.backup_finished)

    def update_progress(self):
        """Update the progress bar and label based on the copied bytes."""
        percent = (self.copied_bytes / self.total_bytes) * 100 if self.total_bytes > 0 else 100
        self.root.after(0, lambda: self.progress_bar.config(value=percent))
        self.root.after(0, lambda: self.progress_label.config(text=f"Progress: {percent:.2f}%"))

    def cancel_backup_operation(self):
        """Signal the backup process to cancel."""
        self.cancel_backup = True
        self.cancel_btn.config(text="Cancelling...", state="disabled")
        self.log_message("Backup cancellation requested.", level="warning")

    def backup_finished(self):
        """Handle completion of the backup process."""
        self.enable_ui()
        self.cancel_btn.config(state="disabled")
        messagebox.showinfo("Backup Complete", "All files have been backed up.")
        self.log_message("Backup completed successfully.", level="info")

    def backup_canceled(self):
        """Handle backup cancellation."""
        self.enable_ui()
        self.cancel_btn.config(state="disabled")
        messagebox.showinfo("Backup Canceled", "Backup operation has been canceled.")
        self.log_message("Backup was canceled.", level="warning")

    def disable_ui(self):
        """Disable interactive UI elements during backup."""
        self.add_btn.config(state="disabled")
        self.remove_btn.config(state="disabled")
        self.dest_entry.config(state="disabled")
        self.dest_btn.config(state="disabled")
        self.source_listbox.config(state="disabled")
        self.start_btn.config(state="disabled")

    def enable_ui(self):
        """Re-enable interactive UI elements after backup."""
        self.add_btn.config(state="normal")
        self.remove_btn.config(state="normal")
        self.dest_entry.config(state="normal")
        self.dest_btn.config(state="normal")
        self.source_listbox.config(state="normal")
        self.start_btn.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = BackupApp(root)
    root.mainloop()
