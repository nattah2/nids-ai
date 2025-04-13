{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  # Specify the packages to include in the environment
  buildInputs = [
    # Nix deployment
    pkgs.nixops_unstable_minimal

    # Packet capture and analysis
    pkgs.wireshark
    pkgs.tcpdump
    pkgs.zeek

    # Traffic simulation
    pkgs.iperf
    pkgs.ostinato
    pkgs.python3Packages.selenium
    pkgs.chromedriver
    pkgs.chromium
    # pkgs.apache-jmeter

    # Attack simulation
    pkgs.metasploit
    pkgs.nmap
    pkgs.chromedriver
    pkgs.chromium
    pkgs.hping
    pkgs.sqlmap

    # Data analysis and preprocessing
    pkgs.python3
    pkgs.jupyter-all
    pkgs.python3Packages.seaborn
    pkgs.python3Packages.scapy
    pkgs.python3Packages.pandas
    pkgs.python3Packages.numpy
    pkgs.python3Packages.scikit-learn
    pkgs.python3Packages.ipywidgets

    # Virtualization and network emulation
    pkgs.virtualbox
    pkgs.gns3-gui
    pkgs.mininet

    # Miscellaneous utilities
    pkgs.curl
    pkgs.git
    pkgs.vim
  ];

  # Environment variables (optional)
  shellHook = ''
    echo "Welcome to the NIDS development environment!"
    echo "Available tools:"
    echo "- Packet capture: Wireshark, tcpdump, Zeek"
    echo "- Traffic simulation: iperf, Ostinato, Apache JMeter"
    echo "- Attack simulation: Metasploit, Nmap, hping, SQLMap"
    echo "- Data analysis: Python, Scapy, Pandas, NumPy, Scikit-learn"
    echo "- Virtualization: VirtualBox, GNS3, Mininet"

    jupyter notebook & disown
  '';
}
