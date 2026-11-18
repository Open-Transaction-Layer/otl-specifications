# Scope

This Working Group develops the specifications of the Open Transaction Layer (OTL) protocol.

OTL specifies how participants in digital asset transactions establish verifiable identity, authorise actions, connect, and exchange signed and encrypted data with each other. Participants include regulated institutions, individual wallet holders and software agents, acting for themselves or on behalf of others. The specifications are transport-agnostic: the data they define can be carried over any transport, including existing channels.

The specifications cover:

- Identity: decentralized identifiers, whether published off-chain or on-chain; publication of keys and service endpoints; verifiable credentials and attestations about participants and their addresses, including how they are issued, presented, revoked and validated; and delegation of authority between participants.
- Session establishment: how a party discovers and joins a transaction session.
- Transport: authenticated, end-to-end encrypted exchange of data between participants, and how OTL data is carried over other transports.
- Data objects: schemas for transaction data, including transaction instructions, originator and beneficiary information, address ownership proofs, credential presentations and settlement notifications.
- Applications: end-to-end interactions built on one or more of these layers, including participant roles, message sequences and states, for transaction and compliance use cases.

The specifications do not cover:

- how a participant decides whether to trust a counterparty or accept a transaction;
- key generation, storage, custody or signing implementations.

Any changes of Scope are not retroactive.
