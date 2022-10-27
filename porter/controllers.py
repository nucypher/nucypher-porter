
from nucypher.control.controllers import CLIController
from nucypher.control.emitters import StdoutEmitter


class PorterCLIController(CLIController):

    _emitter_class = StdoutEmitter

    def __init__(self,
                 interface: 'PorterInterface',
                 *args,
                 **kwargs):
        super().__init__(interface=interface, *args, **kwargs)

    def _perform_action(self, *args, **kwargs) -> dict:
        try:
            response_data = super()._perform_action(*args, **kwargs)
        finally:
            self.log.debug(f"Finished action '{kwargs['action']}', stopping {self.interface.implementer}")
            self.interface.implementer.disenchant()
        return response_data
