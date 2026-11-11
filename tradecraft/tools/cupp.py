from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.cupp import execute as cupp_execute
from tradecraft.adapters.cupp import parse as cupp_parse
from tradecraft.tools.base import Tool


class Cupp(Tool):
    tool_id = "cupp"

    def is_available(self) -> bool:
        return cupp_execute.is_available()

    def run(
        self,
        name: str,
        surname: str = "",
        nickname: str = "",
        birthdate: str = "",
        partner_name: str = "",
        partner_nickname: str = "",
        partner_birthdate: str = "",
        child_name: str = "",
        child_nickname: str = "",
        child_birthdate: str = "",
        pet_name: str = "",
        company: str = "",
        keywords: str = "",
        add_special_chars: bool = False,
        add_random_numbers: bool = False,
        leet_mode: bool = False,
    ) -> Dict[str, Any]:
        raw = cupp_execute.execute(
            name=name,
            surname=surname,
            nickname=nickname,
            birthdate=birthdate,
            partner_name=partner_name,
            partner_nickname=partner_nickname,
            partner_birthdate=partner_birthdate,
            child_name=child_name,
            child_nickname=child_nickname,
            child_birthdate=child_birthdate,
            pet_name=pet_name,
            company=company,
            keywords=keywords,
            add_special_chars=add_special_chars,
            add_random_numbers=add_random_numbers,
            leet_mode=leet_mode,
        )
        return cupp_parse.parse_cupp_result(raw)
