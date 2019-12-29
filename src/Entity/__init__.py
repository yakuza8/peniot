"""
    This package contains the following entities:

    1) Protocol
    2) Attack Suite
    3) Attack
    4) Input Format

    In this module, we have the backend entities to represent and structure our code
    And these entities have the following relations in between: (Connection endpoints represent cardinality of entity)

    - Protocol      1----------*    Attack Suite
    - Attack suite  1----------*    Attack
    - Attack        1----------*    Input format
"""