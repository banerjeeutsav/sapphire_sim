# Sapphire-Sim: Macro-Op-Level Simulator for Ring-LWE and Module-LWE Hardware Acceleration

Saphire-Sim is a Python-based cycle-accurate simulator for the [Sapphire](https://tches.iacr.org/index.php/TCHES/article/view/8344) crypto-processor, which can be used to profile the power consumption and performance of algorithms based on Ring-LWE and Module-LWE.

In the original test chip, the Sapphire crypto-core was integrated with a RISC-V micro-processor through its memory-mapped interface. However, the simulator currently replicates functionality of the crypto-core only, that is, neither RISC-V programs nor data movement between the RISC-V processor and the crypto-core can be simulated. Please note that this is not an architectural simulator, that is, it is only functionally correct and does not replicate any internal circuitry of the crypto-core (unlike an HDL-based RTL simulation).

The simulator currently supports polynomial dimension {64, 128, 256, 512, 1024, 2048} and prime modulus {3329, 7681, 12289, 40961, 65537, 120833, 133121, 184321, 4205569, 4206593, 8058881, 8380417, 8404993}. Polynomials can be sampled from various discrete probability distributions with configurable parameters. Custom instructions supported by the crypto-processor are summarized [here](documentation.pdf).

### Usage

The Sapphire-Sim simulator can be run using Python (requires Python 3) as follows:

```
python sim.py --prog <program_file_path>
              --vdd <voltage>
              --fmhz <frequency_mhz>
              [ --verbose ]
              [ --free_rw ]
              [ --plot_power ]
              [ --cdt <cdt_file_path> ]
              [ --iter <num_iterations> ]
```

where ```--prog```, ```--vdd```, ```--fmhz``` are mandatory arguments providing the program file path, supply voltage (in 0.68-1.21 V), operating frequency (in MHz) respectively. The simulator checks whether the operating frequency is below the maximum allowed frequency at specified supply voltage.

At the end of simulation, the following information are summarized:
- Number of instructions executed (including branching)
- Total cycle count and execution time
- Average power consumption
- Total energy consumption

The optional ```--verbose``` flag is used to enable or disable ```print``` instructions to display registers and polynomials. The optional ```--free_rw``` flag is used to enable or disable ```load``` / ```save``` / ```random``` instructions to skip cycle count and power consumption overheads associated with the crypto-processor's read-write interface.

The optional ```--plot_power``` flag is used to enable or disable displaying the power consumption of the crypto-core as a function of time during program execution. Please note that this plot only provides a coarse estimate of the power consumption (only average power at the macro-op level) and is not at all intended (or suitable) for side-channel analysis.

The optional ```--cdt``` flag is used to provide the CDT file path in case CDT-based sampling is used.

The ```--iter``` option can be used to indicate the number of iterations of program execution. When the specified number of iterations is greater than one, simulation summaries are reported for each iteration. At the end of all iterations, the average cycle count, power and energy consumption over all iterations are reported.

### Detailed Documentation

For detailed description of the Sapphire crypto-processor, supported instructions, example code and instructions for Sapphire-Sim, please refer to this [document](documentation.pdf).

### Bibliography

If you find this tool useful for your research, please consider citing the following:

```
@article{sapphire_ches_2019,
  title={{Sapphire: A Configurable Crypto-Processor for Post-Quantum Lattice-based Protocols}},
  author={U. {Banerjee} and T. S. {Ukyab} and A. P. {Chandrakasan}},
  journal={IACR Transactions on Cryptographic Hardware and Embedded Systems},
  volume={2019},
  number={4},
  pages={17-61},
  month={Aug.},
  year={2019}
}
```

### License

The Keccak implementation in [keccak.py](keccak.py) is taken from [keccak-python](https://github.com/mgoffin/keccak-python/) which is in public domain. All other files in this project are licensed under the MIT License - please refer to the [LICENSE](LICENSE) file for details.
