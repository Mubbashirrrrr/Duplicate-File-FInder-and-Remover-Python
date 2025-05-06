import os
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.font import Font
from threading import Thread
from queue import Queue
import time

class DuplicateFileFinder:
    def __init__(self, root):
        self.root = root
        self.setup_ui()
        self.duplicates = []
        self.running = False
        self.queue = Queue()
        self.progress = {"value": 0, "max": 100, "text": ""}
        
    def setup_ui(self):
        # Configure main window
        self.root.title("Duplicate File Finder & Remover")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Custom fonts
        title_font = Font(family="Helvetica", size=14, weight="bold")
        button_font = Font(family="Helvetica", size=10)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding=(20, 10))
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(
            header_frame, 
            text="Duplicate File Finder", 
            font=title_font,
            foreground="#4a6ea9"
        ).pack(side=tk.LEFT)
        
        # Settings frame
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding=(15, 10))
        settings_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Directory selection
        dir_frame = ttk.Frame(settings_frame)
        dir_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dir_frame, text="Directory:").pack(side=tk.LEFT)
        self.dir_entry = ttk.Entry(dir_frame)
        self.dir_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(
            dir_frame, 
            text="Browse", 
            command=self.browse_directory
        ).pack(side=tk.LEFT)
        
        # Algorithm selection
        algo_frame = ttk.Frame(settings_frame)
        algo_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(algo_frame, text="Hash Algorithm:").pack(side=tk.LEFT)
        self.algo_var = tk.StringVar(value="SHA-256")
        algo_menu = ttk.Combobox(
            algo_frame, 
            textvariable=self.algo_var,
            values=["MD5", "SHA-1", "SHA-256"],
            state="readonly",
            width=10
        )
        algo_menu.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(
            settings_frame,
            orient=tk.HORIZONTAL,
            mode='determinate'
        )
        self.progress_bar.pack(fill=tk.X, pady=5)
        self.progress_label = ttk.Label(settings_frame, text="Ready")
        self.progress_label.pack(fill=tk.X)
        
        # Action buttons
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            button_frame,
            text="Scan for Duplicates",
            command=self.start_scan_thread
        ).pack(side=tk.LEFT, padx=5)
        
        self.delete_selected_btn = ttk.Button(
            button_frame,
            text="Delete Selected",
            command=self.delete_selected,
            state=tk.DISABLED
        )
        self.delete_selected_btn.pack(side=tk.LEFT)
        
        self.delete_all_btn = ttk.Button(
            button_frame,
            text="Delete All Duplicates",
            command=self.delete_all,
            state=tk.DISABLED
        )
        self.delete_all_btn.pack(side=tk.LEFT, padx=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding=(15, 10))
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview with scrollbars
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tree = ttk.Treeview(
            tree_frame,
            columns=("original", "duplicate", "size"),
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        self.tree.heading("original", text="Original File", anchor=tk.W)
        self.tree.heading("duplicate", text="Duplicate File", anchor=tk.W)
        self.tree.heading("size", text="Size", anchor=tk.W)
        
        self.tree.column("original", width=400, stretch=tk.YES)
        self.tree.column("duplicate", width=400, stretch=tk.YES)
        self.tree.column("size", width=100, stretch=tk.NO)
        
        # Scrollbars
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        y_scroll.grid(row=0, column=1, sticky=tk.NS)
        x_scroll.grid(row=1, column=0, sticky=tk.EW)
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(
            main_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        ).pack(fill=tk.X, pady=(10, 0))
        
        # Start periodic queue check
        self.check_queue()
    
    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)
    
    def update_progress(self, value=None, max_value=None, text=None):
        if value is not None:
            self.progress["value"] = value
        if max_value is not None:
            self.progress["max"] = max_value
        if text is not None:
            self.progress["text"] = text
        
        # Update progress bar
        self.progress_bar["maximum"] = self.progress["max"]
        self.progress_bar["value"] = self.progress["value"]
        self.progress_label.config(text=self.progress["text"])
    
    def check_queue(self):
        """Check for messages from the worker thread"""
        try:
            while True:
                message = self.queue.get_nowait()
                if message == "SCAN_COMPLETE":
                    self.on_scan_complete()
                elif isinstance(message, dict):
                    if "progress" in message:
                        self.update_progress(
                            value=message["progress"]["value"],
                            max_value=message["progress"]["max"],
                            text=message["progress"]["text"]
                        )
                    elif "duplicates" in message:
                        self.add_duplicates_to_tree(message["duplicates"])
        except:
            pass
        
        self.root.after(100, self.check_queue)
    
    def start_scan_thread(self):
        """Start the scan in a separate thread"""
        if self.running:
            return
            
        directory = self.dir_entry.get()
        if not directory:
            messagebox.showerror("Error", "Please select a directory first")
            return
        
        # Reset UI
        self.tree.delete(*self.tree.get_children())
        self.duplicates = []
        self.delete_selected_btn.config(state=tk.DISABLED)
        self.delete_all_btn.config(state=tk.DISABLED)
        
        # Start scan thread
        self.running = True
        Thread(
            target=self.scan_duplicates,
            args=(directory, self.algo_var.get()),
            daemon=True
        ).start()
    
    def scan_duplicates(self, directory, algo):
        """Worker thread function to find duplicates"""
        try:
            file_index = {}
            total_files = 0
            processed_files = 0
            
            # First pass - count files for progress
            for root, _, files in os.walk(directory):
                total_files += len(files)
            
            self.queue.put({
                "progress": {
                    "value": 0,
                    "max": total_files,
                    "text": "Counting files..."
                }
            })
            
            # Second pass - find duplicates
            hash_func = {
                "MD5": hashlib.md5,
                "SHA-1": hashlib.sha1,
                "SHA-256": hashlib.sha256
            }[algo]
            
            duplicates_found = []
            total_size = 0
            
            for root, _, files in os.walk(directory):
                for filename in files:
                    if not self.running:
                        return
                        
                    filepath = os.path.join(root, filename)
                    try:
                        # Calculate file hash
                        file_hash = hash_func()
                        with open(filepath, "rb") as f:
                            for chunk in iter(lambda: f.read(8192), b""):
                                file_hash.update(chunk)
                        file_hash = file_hash.hexdigest()
                        
                        # Get file size
                        file_size = os.path.getsize(filepath)
                        
                        # Check for duplicates
                        if file_hash in file_index:
                            original_path, original_size = file_index[file_hash]
                            duplicates_found.append((original_path, filepath, file_size))
                            total_size += file_size
                        else:
                            file_index[file_hash] = (filepath, file_size)
                            
                        processed_files += 1
                        
                        # Update progress every 10 files
                        if processed_files % 10 == 0:
                            self.queue.put({
                                "progress": {
                                    "value": processed_files,
                                    "max": total_files,
                                    "text": f"Scanned {processed_files}/{total_files} files"
                                }
                            })
                    except Exception as e:
                        print(f"Error processing {filepath}: {e}")
                        continue
            
            # Send results to main thread
            self.queue.put({
                "duplicates": duplicates_found,
                "total_size": total_size
            })
            self.queue.put("SCAN_COMPLETE")
            
        finally:
            self.running = False
    
    def add_duplicates_to_tree(self, duplicates):
        """Add found duplicates to the treeview"""
        self.duplicates = []
        
        for original, duplicate, size in duplicates:
            size_mb = f"{size/1024/1024:.2f} MB"
            self.tree.insert("", tk.END, values=(
                f"{original} ({size_mb})",
                f"{duplicate} ({size_mb})",
                size_mb
            ))
            self.duplicates.append((original, duplicate))
    
    def on_scan_complete(self):
        """Called when scan completes"""
        self.running = False
        self.update_progress(value=0, text="Scan complete")
        
        if self.duplicates:
            self.delete_selected_btn.config(state=tk.NORMAL)
            self.delete_all_btn.config(state=tk.NORMAL)
            self.status_var.set(f"Found {len(self.duplicates)} duplicate files")
        else:
            messagebox.showinfo("Result", "No duplicate files found in the selected directory")
            self.status_var.set("No duplicate files found")
    
    def delete_selected(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "No files selected for deletion")
            return
        
        # First confirmation
        if not messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete {len(selected_items)} selected duplicate files?\n"
            "This action cannot be undone!",
            icon="warning"
        ):
            return
        
        # Second confirmation with count
        if not messagebox.askyesno(
            "Final Confirmation",
            f"Please confirm again - delete {len(selected_items)} files permanently?",
            icon="warning"
        ):
            return
        
        deleted_count = 0
        errors = []
        
        for item in selected_items:
            values = self.tree.item(item, "values")
            dup_path = values[1].split(" (")[0]  # Extract path from display string
            
            try:
                os.remove(dup_path)
                self.tree.delete(item)
                deleted_count += 1
            except Exception as e:
                errors.append(f"{dup_path}: {str(e)}")
        
        # Show results
        result_msg = f"Successfully deleted {deleted_count} files."
        if errors:
            result_msg += f"\n\nFailed to delete {len(errors)} files:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                result_msg += f"\n...and {len(errors)-5} more"
        
        self.status_var.set(f"Deleted {deleted_count} files")
        messagebox.showinfo("Deletion Complete", result_msg)
    
    def delete_all(self):
        if not self.duplicates:
            messagebox.showwarning("Warning", "No duplicates to delete")
            return
        
        # First confirmation
        if not messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete ALL {len(self.duplicates)} duplicate files?\n"
            "This action cannot be undone!",
            icon="warning"
        ):
            return
        
        # Second confirmation with count
        if not messagebox.askyesno(
            "Final Confirmation",
            f"Please confirm again - delete ALL {len(self.duplicates)} files permanently?",
            icon="warning"
        ):
            return
        
        deleted_count = 0
        errors = []
        
        for original, duplicate in self.duplicates:
            try:
                os.remove(duplicate)
                deleted_count += 1
            except Exception as e:
                errors.append(f"{duplicate}: {str(e)}")
        
        # Clear the treeview
        self.tree.delete(*self.tree.get_children())
        self.duplicates = []
        self.delete_selected_btn.config(state=tk.DISABLED)
        self.delete_all_btn.config(state=tk.DISABLED)
        
        # Show results
        result_msg = f"Successfully deleted {deleted_count} files."
        if errors:
            result_msg += f"\n\nFailed to delete {len(errors)} files:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                result_msg += f"\n...and {len(errors)-5} more"
        
        self.status_var.set(f"Deleted {deleted_count} files")
        messagebox.showinfo("Deletion Complete", result_msg)

if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFileFinder(root)
    root.mainloop()