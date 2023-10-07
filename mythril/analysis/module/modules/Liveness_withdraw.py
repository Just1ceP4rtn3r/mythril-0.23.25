"""This module contains the detection code for unauthorized ether
withdrawal."""
import logging
from copy import copy

from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.issue_annotation import IssueAnnotation
from mythril.analysis.report import Issue
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.analysis.swc_data import UNPROTECTED_ETHER_WITHDRAWAL
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.analysis import solver
from mythril.exceptions import UnsatError
from mythril.laser.smt import UGT
from mythril.laser.smt.bool import And

log = logging.getLogger(__name__)

DESCRIPTION = """
Search for cases where Ether can be withdrawn to a user-specified address.
An issue is reported if there is a valid end state where the attacker has successfully
increased their Ether balance.
"""


class Withdraw(DetectionModule):
    """This module search for cases where Ether can be withdrawn to a user-
    specified address."""

    name = "Withdraw"
    swc_id = "Withdraw"
    description = DESCRIPTION
    entry_point = EntryPoint.CALLBACK
    post_hooks = ["CALL", "STATICCALL"]

    def reset_module(self):
        """
        Resets the module by clearing everything
        :return:
        """
        super().reset_module()

    def _execute(self, state: GlobalState) -> None:
        """
        :param state:
        :return:
        """
        return self._analyze_state(state)

    def _analyze_state(self, state):
        """
        :param state:
        :return:
        """


        instruction = state.get_current_instruction()

        constraints = (
                state.world_state.constraints
                + UGT(
                state.world_state.balances[ACTORS.attacker],
                0,
            )
        )

        try:
            transaction_sequence = solver.get_transaction_sequence(
                    state, constraints
                )
            address = state.get_current_instruction()["address"]

            issue = Issue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=address,
                swc_id=self.swc_id,
                title=self.name,
                severity="Medium",
                description_head=self.name,
                description_tail=self.name,
                bytecode=state.environment.code.bytecode,
                transaction_sequence=transaction_sequence,
                gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
            )
            state.annotate(
                IssueAnnotation(
                    detector=self,
                    issue=issue,
                    conditions=[And(*constraints)],
                )
            )
            return [issue]

        except UnsatError:
            return []


detector = Withdraw()
