import tkinter as tk
import queue
import local_server
import bisect
import math
from tkinter import ttk, filedialog
from elftools.elf.elffile import ELFFile

class MemoryBlock:
    def __init__(self, address, size, backtrace=None, timestamp=0):
        self.address = address
        self.size = size
        self.backtrace = backtrace if backtrace is not None else []
        self.timestamp = timestamp

    def __repr__(self):
        return f"[0x{self.address:x}: 0x{self.address + self.size:x} ({self.size} bytes)]"

class SymbolResolver:
    def __init__(self, executable_path):
        self.executable_path = executable_path
        self.func_cache = {}
        self.func_ranges = []
        try:
            self.elffile = ELFFile(open(executable_path, 'rb'))
            if not self.elffile.has_dwarf_info():
                print("Executable has no DWARF info.")
                self.dwarfinfo = None
                return

            self.dwarfinfo = self.elffile.get_dwarf_info()
            self._parse_functions()

        except Exception as e:
            print(f"Error initializing SymbolResolver: {e}")
            self.dwarfinfo = None

    def _get_die_name(self, die):
        if 'DW_AT_name' in die.attributes:
            return die.attributes['DW_AT_name'].value.decode('utf-8', 'ignore')
        
        if 'DW_AT_specification' in die.attributes:
            spec_offset = die.attributes['DW_AT_specification'].value + die.cu.cu_offset
            spec_die = self.dwarfinfo.get_DIE_from_refaddr(spec_offset)
            return self._get_die_name(spec_die)

        if 'DW_AT_abstract_origin' in die.attributes:
            ao_offset = die.attributes['DW_AT_abstract_origin'].value + die.cu.cu_offset
            ao_die = self.dwarfinfo.get_DIE_from_refaddr(ao_offset)
            return self._get_die_name(ao_die)
        
        return None

    def _parse_functions(self):
        if self.dwarfinfo is None:
            return
        
        print("Parsing DWARF info for function ranges...")
        elf_base = 0
        for segment in self.elffile.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                elf_base = segment['p_vaddr']
                break

        for CU in self.dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag == 'DW_TAG_subprogram':
                    try:
                        if 'DW_AT_low_pc' not in DIE.attributes:
                            continue
                        
                        func_name = self._get_die_name(DIE)
                        if func_name is None:
                            continue

                        low_pc = DIE.attributes['DW_AT_low_pc'].value
                        
                        high_pc_attr = DIE.attributes.get('DW_AT_high_pc')
                        if high_pc_attr is None:
                            continue
                        
                        high_pc = high_pc_attr.value
                        if high_pc_attr.form != 'DW_FORM_addr':
                            high_pc += low_pc
                        
                        self.func_ranges.append((low_pc - elf_base, high_pc - elf_base, func_name))

                    except Exception:
                        continue
        
        self.func_ranges.sort()
        print(f"Finished parsing. Found {len(self.func_ranges)} functions.")

    def resolve(self, address):
        if address in self.func_cache:
            return self.func_cache[address]

        idx = bisect.bisect_right(self.func_ranges, (address, float('inf')))
        
        if idx > 0:
            start_addr, end_addr, name = self.func_ranges[idx - 1]
            if start_addr <= address < end_addr:
                self.func_cache[address] = name
                return name

        self.func_cache[address] = f"0x{address:x}"
        return f"0x{address:x}"

class StartupDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Select Executable")
        self.geometry("500x150")
        self.executable_path = None

        self.transient(parent)
        
        # Center the dialog on screen
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
        
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Please provide the path to the debug-enabled executable:").pack(anchor=tk.W)

        path_frame = ttk.Frame(main_frame)
        path_frame.pack(fill=tk.X, pady=10)

        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_button = ttk.Button(path_frame, text="Browse...", command=self.browse_file)
        browse_button.pack(side=tk.LEFT, padx=(5, 0))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(10,0))

        continue_button = ttk.Button(button_frame, text="Continue", command=self.on_continue)
        continue_button.pack(side=tk.RIGHT)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.on_cancel)
        cancel_button.pack(side=tk.RIGHT, padx=(0, 5))

        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        path_entry.focus_set()

    def browse_file(self):
        path = filedialog.askopenfilename(title="Select executable with debug symbols")
        if path:
            self.path_var.set(path)

    def on_continue(self):
        path = self.path_var.get()
        if path:
            self.executable_path = path
            self.destroy()

    def on_cancel(self):
        self.executable_path = None
        self.destroy()

class MemoryVisualizer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Allocations Visualizer")
        self.geometry("1200x800")

        # Center the dialog on screen
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

        self.memory_map = {}
        self.queue = queue.Queue()
        self.symbol_resolver = None
        
        # Create an empty placeholder frame initially
        self.placeholder_frame = ttk.Frame(self)
        self.placeholder_frame.pack(fill=tk.BOTH, expand=True)
        
        # Schedule the dialog to appear after the main window is ready
        self.after(100, self.show_startup_dialog)

    def show_startup_dialog(self):
        dialog = StartupDialog(self)
        self.wait_window(dialog)
        
        executable_path = dialog.executable_path
        if not executable_path:
            self.destroy()
            return

        # Remove placeholder and show actual UI
        self.placeholder_frame.destroy()
        
        self.symbol_resolver = SymbolResolver(executable_path)
        self.setup_ui()
        local_server.start_server(self.queue)
        self.process_queue()

    def setup_ui(self):
        self.paned_window = ttk.PanedWindow(self, orient=tk.VERTICAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        map_frame = ttk.Frame(self.paned_window, padding="5")
        self.paned_window.add(map_frame, weight=1)

        map_top_bar = ttk.Frame(map_frame)
        map_top_bar.pack(fill=tk.X)
        ttk.Label(map_top_bar, text="Memory Usage Heatmap").pack(side=tk.LEFT)
        self.total_mem_var = tk.StringVar()
        ttk.Label(map_top_bar, textvariable=self.total_mem_var).pack(side=tk.RIGHT)

        self.heatmap_canvas = tk.Canvas(map_frame, bg="white", height=100)
        self.heatmap_canvas.pack(fill=tk.BOTH, expand=True)

        stats_frame = ttk.Frame(self.paned_window, padding="5")
        self.paned_window.add(stats_frame, weight=3)
        ttk.Label(stats_frame, text="Allocation Statistics by Call Stack").pack(anchor=tk.W)
        self.stats_tree = ttk.Treeview(stats_frame, columns=("Allocations", "Total Size"))
        self.stats_tree.heading('#0', text='Function / Call Stack')
        self.stats_tree.heading("Allocations", text="Allocations")
        self.stats_tree.heading("Total Size", text="Total Size (KB)")
        self.stats_tree.column('#0', width=500)
        self.stats_tree.column("Allocations", width=100, anchor=tk.E)
        self.stats_tree.column("Total Size", width=150, anchor=tk.E)
        self.stats_tree.pack(fill=tk.BOTH, expand=True)

    def process_queue(self):
        try:
            updated = False
            for _ in range(500):
                if self.queue.empty():
                    break
                data = self.queue.get_nowait()
                self._handle_data_line(data)
                updated = True

            if updated:
                self.update_ui()
        finally:
            self.after(100, self.process_queue)

    def _handle_data_line(self, data):
        line = data.decode('utf-8')
        try:
            parts = line.split()
            if not parts:
                return
            
            command = parts[0]
            if command == 'M':
                addr = int(parts[1], 16)
                size = int(parts[2])
                ts_sec, ts_nsec = int(parts[3]), int(parts[4])
                timestamp = ts_sec + ts_nsec / 1e9
                backtrace = [int(p, 16) for p in parts[5:] if p]
                self.memory_map[addr] = MemoryBlock(addr, size, backtrace, timestamp)
            elif command == 'F':
                addr = int(parts[1], 16)
                if addr in self.memory_map:
                    del self.memory_map[addr]
            elif command == 'C':
                addr = int(parts[1], 16)
                nmemb, size = int(parts[2]), int(parts[3])
                ts_sec, ts_nsec = int(parts[4]), int(parts[5])
                timestamp = ts_sec + ts_nsec / 1e9
                total_size = nmemb * size
                backtrace = [int(p, 16) for p in parts[6:] if p]
                self.memory_map[addr] = MemoryBlock(addr, total_size, backtrace, timestamp)
            elif command == 'R':
                old_addr = int(parts[1], 16)
                new_addr = int(parts[2], 16)
                size = int(parts[3])
                ts_sec, ts_nsec = int(parts[4]), int(parts[5])
                timestamp = ts_sec + ts_nsec / 1e9
                backtrace = [int(p, 16) for p in parts[6:] if p]
                if old_addr in self.memory_map:
                    del self.memory_map[old_addr]
                self.memory_map[new_addr] = MemoryBlock(new_addr, size, backtrace, timestamp)
        except (ValueError, IndexError) as e:
            print(f"Skipping malformed line: '{line}'. Error: {e}")

    def update_ui(self):
        self.update_heatmap_view()
        self.update_stats_view()
        self.update_total_size_label()

    def update_total_size_label(self):
        total_size = sum(block.size for block in self.memory_map.values())
        if total_size > 1024 * 1024:
            size_str = f"{total_size / (1024 * 1024):.2f} MB"
        elif total_size > 1024:
            size_str = f"{total_size / 1024:.2f} KB"
        else:
            size_str = f"{total_size} Bytes"
        self.total_mem_var.set(f"Total Allocated: {size_str}")

    def update_heatmap_view(self):
        self.heatmap_canvas.delete("all")
        if not self.memory_map:
            return

        sorted_blocks = sorted(self.memory_map.values(), key=lambda b: b.address)
        
        regions = []
        if sorted_blocks:
            current_region = [sorted_blocks[0]]
            regions.append(current_region)
            last_addr = sorted_blocks[0].address + sorted_blocks[0].size
            GAP_THRESHOLD = 16 * 1024 * 1024

            for block in sorted_blocks[1:]:
                if (block.address - last_addr) > GAP_THRESHOLD:
                    current_region = [block]
                    regions.append(current_region)
                else:
                    current_region.append(block)
                last_addr = block.address + block.size

        canvas_width = self.heatmap_canvas.winfo_width()
        if canvas_width <= 1: return

        total_regions = len(regions)
        if total_regions == 0: return

        separator_width = 5
        total_separator_width = separator_width * (total_regions - 1)
        available_width = canvas_width - total_separator_width
        
        all_regions_span = sum((max(b.address + b.size for b in r) - r[0].address) for r in regions)
        if all_regions_span == 0: return

        current_x = 0
        for i, region_blocks in enumerate(regions):
            region_span = (max(b.address + b.size for b in region_blocks) - region_blocks[0].address)
            region_width = available_width * (region_span / all_regions_span)

            if region_width >= 1:
                self._draw_heatmap_for_region(region_blocks, current_x, region_width)
            
            current_x += region_width
            if i < total_regions - 1:
                self.heatmap_canvas.create_line(current_x, 0, current_x, self.heatmap_canvas.winfo_height(), fill='black', width=2)
                current_x += separator_width

    def _draw_heatmap_for_region(self, blocks, canvas_x_start, canvas_width):
        min_addr = blocks[0].address
        max_addr = max(b.address + b.size for b in blocks)
        total_mem_range = max_addr - min_addr

        if total_mem_range == 0: return

        num_columns = int(canvas_width)
        if num_columns <= 1: return

        mem_per_column = total_mem_range / num_columns
        if mem_per_column == 0: return

        column_allocated_bytes = [0] * num_columns

        for block in blocks:
            start_col = int((block.address - min_addr) / mem_per_column)
            end_col = int((block.address + block.size - min_addr) / mem_per_column)
            
            for i in range(start_col, min(end_col + 1, num_columns)):
                col_start_mem = min_addr + i * mem_per_column
                col_end_mem = col_start_mem + mem_per_column
                
                overlap_start = max(col_start_mem, block.address)
                overlap_end = min(col_end_mem, block.address + block.size)

                if overlap_end > overlap_start:
                    overlap_size = overlap_end - overlap_start
                    column_allocated_bytes[i] += overlap_size

        log_values = [0.0] * num_columns
        max_log_value = 0.0
        for i, byte_count in enumerate(column_allocated_bytes):
            if byte_count > 0:
                log_values[i] = math.log1p(byte_count)
                if log_values[i] > max_log_value:
                    max_log_value = log_values[i]

        canvas_height = self.heatmap_canvas.winfo_height()
        for i, log_value in enumerate(log_values):
            occupancy = 0.0
            if max_log_value > 0:
                occupancy = log_value / max_log_value
            
            red = int(255 * occupancy)
            green = int(255 * (1 - occupancy))
            color = f'#{red:02x}{green:02x}00'
            x0 = canvas_x_start + i
            self.heatmap_canvas.create_rectangle(x0, 0, x0 + 1, canvas_height, fill=color, outline="")

    def update_stats_view(self):
        open_paths = set()
        def find_open_nodes(parent_node, current_path):
            for child_id in self.stats_tree.get_children(parent_node):
                child_text = self.stats_tree.item(child_id, 'text')
                new_path = current_path + (child_text,)
                if self.stats_tree.item(child_id, 'open'):
                    open_paths.add(new_path)
                    find_open_nodes(child_id, new_path)
        find_open_nodes("", tuple())

        self.stats_tree.delete(*self.stats_tree.get_children())

        allocations_tree = {}
        for block in self.memory_map.values():
            if not block.backtrace:
                continue

            call_stack = [self.symbol_resolver.resolve(addr) for addr in block.backtrace]
            app_call_stack = [frame for frame in call_stack if not frame.startswith("0x")]
            
            if not app_call_stack:
                continue

            app_call_stack.reverse()

            current_level = allocations_tree
            for func_name in app_call_stack:
                if func_name not in current_level:
                    current_level[func_name] = {"count": 0, "size": 0, "children": {}}
                
                current_level[func_name]["count"] += 1
                current_level[func_name]["size"] += block.size
                current_level = current_level[func_name]["children"]

        def populate_tree(parent_node, children_dict, current_path):
            sorted_children = sorted(children_dict.items(), key=lambda item: item[1]['size'], reverse=True)
            for name, data in sorted_children:
                new_path = current_path + (name,)
                is_open = new_path in open_paths
                node_id = self.stats_tree.insert(parent_node, "end", text=name, values=(data["count"], f"{data['size'] // 1024} KB"), open=is_open)
                populate_tree(node_id, data["children"], new_path)

        populate_tree("", allocations_tree, tuple())

if __name__ == "__main__":
    app = MemoryVisualizer()
    app.mainloop()