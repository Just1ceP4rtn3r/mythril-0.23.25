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
from mythril.laser.smt import ULT,UGT
from mythril.laser.smt.bool import And
from mythril.analysis.potential_issues import (
    get_potential_issues_annotation,
    PotentialIssue,
)
from mythril.laser.smt import symbol_factory
from mythril.laser.ethereum.function_managers import keccak_function_manager

log = logging.getLogger(__name__)

DESCRIPTION = """
Search for cases where Ether can be withdrawn to a user-specified address.
An issue is reported if there is a valid end state where the attacker has successfully
increased their Ether balance.
"""


class TokenWithdraw(DetectionModule):
    """This module search for cases where Ether can be withdrawn to a user-
    specified address."""

    name = "TokenDeposit"
    swc_id = "TokenDeposit"
    description = DESCRIPTION
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["SSTORE"]

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
        potential_issues = self._analyze_state(state)

        annotation = get_potential_issues_annotation(state)
        annotation.potential_issues.extend(potential_issues)

    def _analyze_state(self, state):
        """
        :param state:
        :return:
        """
        write_slot = state.mstate.stack[-1]
        value = state.mstate.stack[-2]

        token_slot_attacker = keccak_function_manager.create_keccak(symbol_factory.BitVecVal(0x000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0000000000000000000000000000000000000000000000000000000000000000, 512))

        # log.error(write_slot)
        # log.error(write_slot.size())



        contract_account = None
        before_token = None
        for account in state.world_state.accounts:
            if(account != ACTORS.creator.value and account != ACTORS.attacker.value and account != ACTORS.someguy.value):
                # log.error(account)
                # log.error(state.world_state.accounts[account].contract_name)
                contract_account = state.world_state.accounts[account]
                break

        before_token = contract_account.storage[token_slot_attacker]



        constraints = state.world_state.constraints + [
            write_slot == token_slot_attacker,
            UGT(value, before_token)
        ]


        potential_issue = PotentialIssue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=state.get_current_instruction()["address"],
            swc_id=self.swc_id,
            title=self.name,
            severity="Medium",
            bytecode=state.environment.code.bytecode,
            description_head=self.name,
            description_tail=self.name,
            detector=self,
            constraints=constraints,
        )

        return [potential_issue]

detector = TokenWithdraw()
