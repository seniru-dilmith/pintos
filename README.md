# Pintos Project

![Pintos OS](https://upload.wikimedia.org/wikipedia/commons/thumb/1/1e/Computer_screen_with_code.jpg/800px-Computer_screen_with_code.jpg)

## Overview
Pintos is an educational operating system designed for teaching OS concepts. This repository contains my implementations and modifications for various Pintos labs.

## Repository Structure

This repository consists of multiple branches, each corresponding to different parts of the Pintos project:

- **`main-branch`** - Initial repository setup.
- **`lab-01`** - Lab 01 implementation.
- **`lab-02`** - Lab 02 implementation.

## Getting Started
To set up and run Pintos on your local machine:

1. Clone the repository:
   ```sh
   git clone https://github.com/seniru-dilmith/pintos.git
   cd pintos
   ```
2. Checkout the desired branch:
   ```sh
   git checkout lab-01  # or lab-02
   ```
3. Install dependencies:
   ```sh
   sudo apt-get install qemu gcc make perl
   ```
4. Build the project:
   ```sh
   cd src
   make
   ```
5. Run Pintos:
   ```sh
   pintos -- run 'your-test-program'
   ```

## Labs
Each lab contains specific tasks and solutions for understanding OS internals:
- **Lab 01:** Introduction to threads and scheduling.
- **Lab 02:** Implementing user programs.

## Resources
- [Pintos Documentation](https://web.stanford.edu/class/cs140/projects/pintos/pintos_1.html)
- [OSDev Wiki](https://wiki.osdev.org/Main_Page)

## Contributing
If you'd like to contribute or suggest improvements, feel free to open an issue or create a pull request!

## License
This project follows the MIT License. See [LICENSE](LICENSE) for details.

