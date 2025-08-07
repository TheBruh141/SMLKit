from enum import Enum
from dataclasses import dataclass
from builder import Builder


class ProgrammingLanguage(Enum):
    PYTHON = "Python"
    JAVA = "Java"
    CPP = "C++"
    C = "C"
    JAVASCRIPT = "JavaScript"
    GO = "Go"


@dataclass
class Framework:
    main_lang: ProgrammingLanguage
    name: str
    setup_instructions: Builder


@dataclass
class Project:
    main_lang: ProgrammingLanguage
    framework: Framework
