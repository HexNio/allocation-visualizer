
# Allocation Visualizer

  > **Warning:** This application is highly unstable, and its output cannot be fully trusted. Use this application at your own risk.

This is a real-time, remote memory allocation monitoring tool. It is designed to trace memory operations (e.g. `malloc`, `free`, `calloc`, `realloc`) in a target application running on a resource-constrained like embedded systems and visualize the data on a local machine.

This project was born out of curiosity and the desire to be able to visualize in real time the allocations that occur in a binary, in order to help software developers identify potential leaks/fragmentation more quickly during debugging.

This is an ongoing project that will undergo many changes over time as I learn to understand how this low-level realm works. If you need production-ready solutions, you should use tools like: [heaptrack](https://github.com/KDE/heaptrack) and [valgrind](https://valgrind.org/).

## Features

*  **Real-time Memory Tracing:** Intercepts memory allocation calls on a remote target.
*  **TCP Data Transfer:** Streams allocation data to a local machine for visualization.
*  **Memory Usage Heatmap:** Provides a high-level, logarithmic visualization of memory fragmentation.
*  **Allocation Statistics Tree:** Hierarchically breaks down memory usage by call stack.
*  **DWARF Symbol Resolution:** Resolves function names from debug symbols for clear analysis.

## Architecture

The project consists of two main components:

1.  **C Tracer (`mem_tracer.c`)**: A shared library that uses `LD_PRELOAD` to hook into the target application's memory functions. It captures allocation data, timestamps, and backtraces, and sends this information over a TCP socket to the local GUI.
2.  **Python GUI (`gui.py`)**: A local desktop application built with Python's Tkinter. It receives data from the tracer, resolves function names from DWARF debug symbols, and presents the information to the user.*

_* it may change in future._

## Screens

![allocation-visualizer-1](https://github.com/user-attachments/assets/ce6b3317-c23b-400f-a835-df5156e65544)



## Getting Started

### Prerequisites

*  **C Compiler:** for building the C components. The build scripts requires a specific path.
*  **Python 3:** For running the GUI application.

### Building

1.  **Tracer Library (`mem_tracer.so`):**

```sh

python build.py -c /your/compiler/path

```

This compiles `mem_tracer.c` into a shared library (`mem_tracer.so`).

### Running

1.  **Local Machine:**

* Run the GUI application:

```sh

python gui.py

```

* The application will prompt you to select the debug-enabled executable corresponding to the application running on the remote target. This is necessary for symbol resolution.

2.  **Remote Target:**

* Copy the compiled `mem_tracer.so` and your target application to the remote system.
* Run your application with `LD_PRELOAD`:

```sh

LD_PRELOAD=/path/of/mem_tracer.so  ./your_application

```

## Project Structure

*  `mem_tracer.c`: The C source for the memory tracer library.
*  `gui.py`: The Python source for the GUI visualization tool.
*  `local_server.py`: The Python TCP server that receives data from the tracer.
*  `build.py`: Python script to build the `mem_tracer.so` library.

## Limitations

Currently is only possible to see the allocation where they happens in the given binary up to the function which invokes the allocation

## ToDo
- [ ] implement the overload for dlopen / dlclose
- [ ] allow user to specify a sysroot in order to allow automatic resolution for shared objects debug symbols
- [ ] allow to locally save sessions
- [ ] add a "record" mode in order allow replay of processed sections
- [ ] map symbols from .debug sections too
- [ ] include test pipelines to ensure output data can be trusted
- [ ] better connection handling
- [ ] proper session cleanup between runs
