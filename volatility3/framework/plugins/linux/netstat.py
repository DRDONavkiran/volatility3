import logging
from typing import Iterable, Callable, Tuple

from volatility3.framework import exceptions, renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux import lsof

vollog = logging.getLogger(__name__)

class Netstat(plugins.PluginInterface):
    """Lists all network connections for all processes."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["AArch64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 1, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    @classmethod
    def list_sockets(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[Tuple[str, int, interfaces.objects.ObjectInterface]]:
        vmlinux = context.modules[kernel_module_name]
        sfop_addr = vmlinux.object_from_symbol("socket_file_ops").vol.offset
        dfop_addr = vmlinux.object_from_symbol("sockfs_dentry_operations").vol.offset

        for task in pslist.PsList.list_tasks(context, vmlinux.name, filter_func):
            task_comm = utility.array_to_string(task.comm)
            pid = int(task.pid)

            # Ensure process layer is added
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                vollog.debug(f"No process layer for PID {pid} ({task_comm})")
                continue

            try:
                fd_generator = lsof.Lsof.list_fds(context, vmlinux.name, filter_func=lambda x: x == pid)
                found_socket = False
                for _, _, _, fd_fields in fd_generator:
                    fd_num, filp, full_path = fd_fields

                    try:
                        if filp.f_op not in (sfop_addr, dfop_addr):
                            vollog.debug(f"FD {fd_num} in PID {pid} ({task_comm}) not a socket")
                            continue

                        dentry = filp.get_dentry()
                        if not dentry:
                            vollog.debug(f"No dentry for FD {fd_num} in PID {pid} ({task_comm})")
                            continue

                        d_inode = dentry.d_inode
                        if not d_inode:
                            vollog.debug(f"No inode for FD {fd_num} in PID {pid} ({task_comm})")
                            continue

                        socket_alloc = linux.LinuxUtilities.container_of(
                            d_inode, "socket_alloc", "vfs_inode", vmlinux
                        )
                        socket = socket_alloc.socket

                        if not context.layers[proc_layer_name].is_valid(
                            socket.vol.offset, socket.vol.size
                        ):
                            vollog.debug(f"Invalid socket address {socket.vol.offset:#x} for PID {pid}")
                            continue

                        socket = socket.dereference().cast("socket")
                        found_socket = True
                        yield task_comm, pid, socket

                    except exceptions.InvalidAddressException as e:
                        vollog.warning(f"Skipping socket FD {fd_num} for PID {pid} ({task_comm}): {e}")
                        continue
                    except AttributeError as e:
                        vollog.debug(f"Skipping FD {fd_num} for PID {pid} ({task_comm}) due to structure error: {e}")
                        continue

                if not found_socket:
                    vollog.debug(f"No valid sockets found for PID {pid} ({task_comm})")

            except exceptions.InvalidAddressException as e:
                vollog.warning(f"Skipping all FDs for PID {pid} ({task_comm}): {e}")
                continue

    def _generator(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for task_name, pid, socket in self.list_sockets(
            self.context, self.config["kernel"], filter_func=filter_func
        ):
            try:
                family = socket.get_family()

                if family == 1:  # AF_UNIX
                    try:
                        upcb = socket.so_pcb.dereference().cast("unpcb")
                        path = utility.array_to_string(upcb.unp_addr.sun_path)
                    except (exceptions.InvalidAddressException, AttributeError):
                        vollog.debug(f"Failed to get UNIX socket path for PID {pid} ({task_name})")
                        path = "N/A"
                    yield (
                        0,
                        (
                            format_hints.Hex(socket.vol.offset),
                            "UNIX",
                            path,
                            0,
                            "",
                            0,
                            "",
                            f"{task_name}/{pid:d}",
                        ),
                    )

                elif family in [2, 30]:  # AF_INET or AF_INET6
                    state = socket.get_state()
                    proto = socket.get_protocol_as_string()

                    try:
                        vals = socket.get_converted_connection_info()
                        if vals:
                            (lip, lport, rip, rport) = vals
                            yield (
                                0,
                                (
                                    format_hints.Hex(socket.vol.offset),
                                    proto,
                                    lip,
                                    lport,
                                    rip,
                                    rport,
                                    state,
                                    f"{task_name}/{pid:d}",
                                ),
                            )
                        else:
                            vollog.debug(f"No connection info for {proto} socket in PID {pid} ({task_name})")
                    except exceptions.InvalidAddressException as e:
                        vollog.warning(f"Skipping {proto} socket for PID {pid} ({task_name}): {e}")

            except exceptions.InvalidAddressException as e:
                vollog.warning(f"Skipping socket at {socket.vol.offset:#x} for PID {pid} ({task_name}): {e}")
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Proto", str),
                ("Local IP", str),
                ("Local Port", int),
                ("Remote IP", str),
                ("Remote Port", int),
                ("State", str),
                ("Process", str),
            ],
            self._generator(),
        )
