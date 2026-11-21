"""Virtualization management: one interface, five hypervisor adapters."""
from .base import POWER_ACTIONS, POWER_RISK, HostInfo, HypervisorAdapter, Snapshot, VirtualDisk, VirtualMachine

__all__ = ["POWER_ACTIONS", "POWER_RISK", "HostInfo", "HypervisorAdapter", "Snapshot", "VirtualDisk", "VirtualMachine"]
