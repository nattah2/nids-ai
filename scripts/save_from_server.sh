# Change this to your VM's SSH connection string
VM_USER="bob"
DEFAULT_TARGET="192.168.122.224"
VM_SSH_PORT=22  # Change if not the default SSH port

# Destination folder on host
DEST_DIR="$HOME/vm_pcaps"
mkdir -p "$DEST_DIR"

# Fetch all .pcap files from /tmp on the VM
scp -P "$VM_SSH_PORT" "$VM_USER@$VM_IP:/tmp/*.pcap" "$DEST_DIR/"

echo "PCAPs collected in $DEST_DIR"
