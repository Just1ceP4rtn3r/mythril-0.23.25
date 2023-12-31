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
from mythril.support.support_args import args

from mythril.analysis.module.modules.ContractAddrUtils import contractaddr

log = logging.getLogger(__name__)

DESCRIPTION = """
Search for cases where Ether can be withdrawn to a user-specified address.
An issue is reported if there is a valid end state where the attacker has successfully
increased their Ether balance.
"""


class Test(DetectionModule):
    """This module search for cases where Ether can be withdrawn to a user-
    specified address."""

    name = "Test"
    swc_id = "Test"
    description = DESCRIPTION
    entry_point = EntryPoint.CALLBACK
    # pre_hooks = ["SSTORE",]
    post_hooks = ["CALL"]

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
        instruction = state.get_current_instruction()


        token_contract_address = symbol_factory.BitVecVal(0x0000000000000000000000000000000000000000000000000000000000000000, 256)

        pool_contract_account = None
        token_contract_account = None

        if(contractaddr.PoolAddr is not None and contractaddr.TokenAddr_1 is not None):
            pool_contract_account = state.world_state.accounts[contractaddr.PoolAddr]
            token_contract_account = state.world_state.accounts[contractaddr.TokenAddr_1]
        else:
            for account in state.world_state.accounts:
                if(account != ACTORS.creator.value and account != ACTORS.attacker.value and account != ACTORS.someguy.value):
                    # log.error("account: "+str(account))
                    # log.error("contract name:"+str(state.world_state.accounts[account].contract_name) if state.world_state.accounts[account].contract_name else "None")

                    # TODO: 分析的contract拥有contract_name，实例化的contract的name则是十六进制地址
                    # mythril.analysis.module.modules.Liveness_test [ERROR]: account: 51421440056055728346017419001665401074216449311
                    # mythril.analysis.module.modules.Liveness_test [ERROR]: contract name:Pool
                    # mythril.analysis.module.modules.Liveness_test [ERROR]: account: 655251735853922694967911662580490717076041977877
                    # mythril.analysis.module.modules.Liveness_test [ERROR]: contract name:0x72c68108a82e82617b93d1be0d7975d762035015
                    if("Pool" in state.world_state.accounts[account].contract_name):
                        contractaddr.PoolAddr = account
                        pool_contract_account = state.world_state.accounts[account]
                        log.error("pool account: "+str(account))
                    else:
                        contractaddr.TokenAddr_1 = account
                        token_contract_account = state.world_state.accounts[account]
                        log.error("token account: "+str(account))

        # if(contractaddr.TokenAddr_1 is not None):
        #     token_contract_account = state.world_state.accounts[contractaddr.TokenAddr_1]
        # else if():
        #     token_contract_account = state.world_state.accounts[pool_contract_account.storage[token_contract_address]]


        token_slot_attacker = keccak_function_manager.create_keccak(symbol_factory.BitVecVal(0x000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0000000000000000000000000000000000000000000000000000000000000000, 512))

        before_token = token_contract_account.storage[token_slot_attacker]
        log.error(before_token)
        # log.error(write_slot)
        # log.error(write_slot.size())
        constraints = state.world_state.constraints


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


        # if instruction["opcode"] == "SSTORE" and token_contract_account is not None:

        #     write_slot = state.mstate.stack[-1]
        #     value = state.mstate.stack[-2]

        #     token_slot_attacker = keccak_function_manager.create_keccak(symbol_factory.BitVecVal(0x000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0000000000000000000000000000000000000000000000000000000000000000, 512))

        #     before_token = token_contract_account.storage[token_slot_attacker]
        #     # log.error(write_slot)
        #     # log.error(write_slot.size())




        #     constraints = state.world_state.constraints + [
        #         write_slot == token_slot_attacker,
        #         ULT(value, before_token)
        #     ]


        #     potential_issue = PotentialIssue(
        #         contract=state.environment.active_account.contract_name,
        #         function_name=state.environment.active_function_name,
        #         address=state.get_current_instruction()["address"],
        #         swc_id=self.swc_id,
        #         title=self.name,
        #         severity="Medium",
        #         bytecode=state.environment.code.bytecode,
        #         description_head=self.name,
        #         description_tail=self.name,
        #         detector=self,
        #         constraints=constraints,
        #     )
        #     return [potential_issue]
        # elif instruction["opcode"] == "CALL" and token_contract_account is not None:


detector = Test()
