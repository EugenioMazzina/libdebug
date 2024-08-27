from dataclasses import dataclass

class BasicBlock:
    start: int=0
    end: int=0
    count: int=0

    def __init__(self, s : int, e : int, c :int) -> None:
        self.start=s
        self.end=e
        self.count=c
        pass