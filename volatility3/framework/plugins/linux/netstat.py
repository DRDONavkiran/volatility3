import logging
from typing import Iterable, Callable, Tuple

from volatility3.framework import exceptions, renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist

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
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
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
    ) -> Iterable[
        Tuple[
            interfaces.objects.ObjectInterface,
            interfaces.objects.ObjectInterface,
            interfaces.objects.ObjectInterface,
        ]
    ]:
        """
        Returns the open socket descriptors of a process

        Return values:
            A tuple of 3 elements:
                1) The name of the process that opened the socket
                2) The process ID of the processed that opened the socket
                3) The address of the associated socket structure
        """
        # This is hardcoded, since a change in the default method would change the expected results
        linuxutils_symbol_table = None  # type: ignore
        for task in pslist.PsList.list_tasks(context, kernel_module_name, filter_func):
            
            if linuxutils_symbol_table is None:
                if constants.BANG not in task.vol.type_name:
                    raise ValueError("Task is not part of a symbol table")
                linuxutils_symbol_table = task.vol.type_name.split(constants.BANG)[0]
            
            task_name = utility.array_to_string(task.comm)
            pid = int(task.pid)

            for filp, _, _ in linux.LinuxUtilities.files_descriptors_for_process(
                context, linuxutils_symbol_table, task
            ):
                try:
                    ftype = filp.f_fglob.get_fg_type()
                except exceptions.InvalidAddressException:
                    continue

                if ftype != "SOCKET":
                    continue

                try:
                    socket = filp.f_fglob.fg_data.dereference().cast("socket")
                except exceptions.InvalidAddressException:
                    continue

                if not context.layers[task.vol.native_layer_name].is_valid(
                    socket.vol.offset, socket.vol.size
                ):
                    continue

                yield task_name, pid, socket

    def _generator(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for task_name, pid, socket in self.list_sockets(
            self.context, self.config["kernel"], filter_func=filter_func
        ):
            family = socket.get_family()

            if family == 1:
                try:
                    upcb = socket.so_pcb.dereference().cast("unpcb")
                    path = utility.array_to_string(upcb.unp_addr.sun_path)
                except exceptions.InvalidAddressException:
                    continue

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

            elif family in [2, 30]:
                state = socket.get_state()
                proto = socket.get_protocol_as_string()

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
