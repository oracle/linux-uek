.. SPDX-License-Identifier: GPL-2.0
.. Copyright © 2019-2024 Daniel P. Smith <dpsmith@apertussolutions.com>

=======================
System Launch Integrity
=======================

:Author: Daniel P. Smith
:Date: August 2024

This document serves to establish a common understanding of what a system
launch is, the integrity concern for system launch, and why using a Root of Trust
(RoT) from a Dynamic Launch may be desirable. Throughout this document,
terminology from the Trusted Computing Group (TCG) and National Institute for
Science and Technology (NIST) is used to ensure that vendor natural language is
used to describe and reference security-related concepts.

System Launch
=============

There is a tendency to only consider the classical power-on boot as the only
means to launch an Operating System (OS) on a computer system. In fact, most
modern processors support two system launch methods. To provide clarity,
it is important to establish a common definition of a system launch: during
a single power life cycle of a system, a system launch consists of an initialization
event, typically in hardware, that is followed by an executing software payload
that takes the system from the initialized state to a running state. Driven by
the Trusted Computing Group (TCG) architecture, modern processors are able to
support two methods of system launch. These two methods of system launch are known
as Static Launch and Dynamic Launch.

Static Launch
-------------

Static launch is the system launch associated with the power cycle of the CPU.
Thus, static launch refers to the classical power-on boot where the
initialization event is the release of the CPU from reset and the system
firmware is the software payload that brings the system up to a running state.
Since static launch is the system launch associated with the beginning of the
power lifecycle of a system, it is therefore a fixed, one-time system launch.
It is because of this that static launch is referred to and thought of as being
"static".

Dynamic Launch
--------------

Modern CPUs architectures provides a mechanism to re-initialize the system to a
"known good" state without requiring a power event. This re-initialization
event is the event for a dynamic launch and is referred to as the Dynamic
Launch Event (DLE). The DLE functions by accepting a software payload, referred
to as the Dynamic Configuration Environment (DCE), that execution is handed to
after the DLE is invoked. The DCE is responsible for bringing the system back
to a running state. Since the dynamic launch is not tied to a power event like
the static launch, this enables a dynamic launch to be initiated at any time
and multiple times during a single power life cycle. This dynamism is the
reasoning behind referring to this system launch as "dynamic".

Because a dynamic launch can be conducted at any time during a single power
life cycle, they are classified into one of two types: an early launch or a
late launch.

:Early Launch: When a dynamic launch is used as a transition from a static
   launch chain to the final Operating System.

:Late Launch: The usage of a dynamic launch by an executing Operating System to
   transition to a “known good” state to perform one or more operations, e.g. to
   launch into a new Operating System.

System Integrity
================

A computer system can be considered a collection of mechanisms that work
together to produce a result. The assurance that the mechanisms are functioning
correctly and producing the expected result is the integrity of the system. To
ensure a system's integrity, there is a subset of these mechanisms, commonly
referred to as security mechanisms, that is present to help ensure the system
produces the expected result or at least detects the potential of an unexpected
result. Since the security mechanisms are relied upon to ensue the integrity of
the system, these mechanisms are trusted. Upon inspection, these security
mechanisms each have a set of properties and these properties can be evaluated
to determine how susceptible a mechanism might be to failure. This assessment is
referred to as the Strength of Mechanism, which allows the trustworthiness of
that mechanism to be quantified.

For software systems, there are two system states for which the integrity is
critical: when the software is loaded into memory and when the software is
executing on the hardware. Ensuring that the expected software is loaded into
memory is referred to as load-time integrity while ensuring that the software
executing is the expected software is the runtime integrity of that software.

Load-time Integrity
-------------------

It is critical to understand what load-time integrity establishes about a
system and what is assumed, i.e. what is being trusted. Load-time integrity is
when a trusted entity, i.e. an entity with an assumed integrity, takes an
action to assess an entity being loaded into memory before it is used. A
variety of mechanisms may be used to conduct the assessment, each with
different properties. A particular property is whether the mechanism creates an
evidence of the assessment. Often either cryptographic signature checking or
hashing are the common assessment operations used.

A signature checking assessment functions by requiring a representation of the
accepted authorities and uses those representations to assess if the entity has
been signed by an accepted authority. The benefit to this process is that
assessment process includes an adjudication of the assessment. The drawbacks
are that 1) the adjudication is susceptible to tampering by the Trusted
Computing Base (TCB), 2) there is no evidence to assert that an untampered
adjudication was completed, and 3) the system must be an active participant in
the key management infrastructure.

A cryptographic hashing assessment does not adjudicate the assessment, but
instead generates evidence of the assessment to be adjudicated independently.
The benefits to this approach is that the assessment may be simple such that it
may be implemented in an immutable mechanism, e.g. in hardware.  Additionally,
it is possible for the adjudication to be conducted where it cannot be tampered
with by the TCB. The drawback is that a compromised environment will be allowed
to execute until an adjudication can be completed.

Ultimately, load-time integrity provides confidence that the correct entity was
loaded and in the absence of a run-time integrity mechanism assumes, i.e.
trusts, that the entity will never become corrupted.

Runtime Integrity
-----------------

Runtime integrity in the general sense is when a trusted entity makes an
assessment of an entity at any point in time during the assessed entity's
execution. A more concrete explanation is the taking of an integrity assessment
of an active process executing on the system at any point during the process'
execution. Often the load-time integrity of an operating system's user-space,
i.e. the operating environment, is confused with the runtime integrity of the
system, since it is an integrity assessment of the "runtime" software. The
reality is that actual runtime integrity is a very difficult problem and thus
not very many solutions are public and/or available. One example of a runtime
integrity solution would be Johns Hopkins Advanced Physics Laboratory's (APL)
Linux Kernel Integrity Module (LKIM).

Trust Chains
============

Building upon the understanding of security mechanisms to establish load-time
integrity of an entity, it is possible to chain together load-time integrity
assessments to establish the integrity of the whole system. This process is
known as transitive trust and provides the concept of building a chain of
load-time integrity assessments, commonly referred to as a trust chain. These
assessments may be used to adjudicate the load-time integrity of the whole
system. This trust chain is started by a trusted entity that does the first
assessment. This first entity is referred to as the Root of Trust(RoT) with the
entities name being derived from the mechanism used for the assessment, i.e.
RoT for Verification (RTV) and RoT for Measurement (RTM).

A trust chain is itself a mechanism, specifically a mechanism of mechanisms,
and therefore it also has a Strength of Mechanism. The factors that contribute
to the strength of a trust chain are:

  - The strength of the chain's RoT
  - The strength of each member of the trust chain
  - The length, i.e. the number of members, of the chain

Therefore, the strongest trust chains should start with a strong RoT and should
consist of members being of low complexity and minimize the number of members
participating. In a more colloquial sense, a trust chain is only as strong as its
weakest link, thus more links increase the probability of a weak link.

Dynamic Launch Components
=========================

The TCG architecture for dynamic launch is composed of a component series
used to set up and then carry out the launch. These components work together to
construct an RTM trust chain that is rooted in the dynamic launch and thus commonly
referred to as the Dynamic Root of Trust for Measurement (DRTM) chain.

What follows is a brief explanation of each component in execution order. A
subset of these components are what establishes the dynamic launch's trust
chain.

Dynamic Configuration Environment Preamble
------------------------------------------

The Dynamic Configuration Environment (DCE) Preamble is responsible for setting
up the system environment in preparation for a dynamic launch. The DCE Preamble
is not a part of the DRTM trust chain.

Dynamic Launch Event
--------------------

The dynamic launch event is the event, typically a CPU instruction, that
triggers the system's dynamic launch mechanism to begin the launch process. The
dynamic launch mechanism is also the RoT for the DRTM trust chain.

Dynamic Configuration Environment
---------------------------------

The dynamic launch mechanism may have resulted in a reset of a portion of the
system. To bring the system back to an adequate state for system software, the
dynamic launch will hand over control to the DCE. Prior to handing over this
control, the dynamic launch will measure the DCE. Once the DCE is complete, it
will proceed to measure and then execute the Dynamic Launch Measured
Environment (DLME).

Dynamic Launch Measured Environment
-----------------------------------

The DLME is the first system kernel to have control of the system, but may not
be the last. Depending on the usage and configuration, the DLME may be the
final/target operating system, or it may be a bootloader that will load the
final/target operating system.

Why DRTM
========

It is a fact that DRTM increases the load-time integrity of the system by
providing a trust chain that has an immutable hardware RoT, uses a limited
number of small, special purpose code to establish the trust chain that starts
the target operating system. As mentioned in the Trust Chain section, these are
the main three factors in driving up the strength of a trust chain. As has been
seen with the BootHole exploit, which in fact did not affect the integrity of
DRTM solutions, the sophistication of attacks targeting system launch is at an
all-time high. There is no reason a system should not employ every available
hardware integrity measure. This is the crux of a defense-in-depth
approach to system security. In the past, the now closed SMI gap was often
pointed to as invalidating DRTM, which in fact was nothing but a straw man
argument. As has continued to be demonstrated, if/when SMM is corrupted, it can
always circumvent all load-time integrity (SRTM and DRTM) because it is a
run-time integrity problem. Regardless, Intel and AMD have both deployed
runtime integrity for SMI and SMM which is tied directly to DRTM such that this
perceived deficiency is now non-existent and the world is moving forward with
an expectation that DRTM must be present.

Glossary
========

.. glossary::
  integrity
    Guarding against improper information modification or destruction, and
    includes ensuring information non-repudiation and authenticity.

    - NIST CNSSI No. 4009 - https://www.cnss.gov/CNSS/issuances/Instructions.cfm

  mechanism
    A process or system that is used to produce a particular result.

    - NIST Special Publication 800-160 (VOLUME 1 ) - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-160v1.pdf

  risk
    A measure of the extent to which an entity is threatened by a potential
    circumstance or event, and typically a function of: (i) the adverse impacts
    that would arise if the circumstance or event occurs; and (ii) the
    likelihood of occurrence.

    - NIST SP 800-30 Rev. 1 - https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf

  security mechanism
    A device or function designed to provide one or more security services
    usually rated in terms of strength of service and assurance of the design.

    - NIST CNSSI No. 4009 - https://www.cnss.gov/CNSS/issuances/Instructions.cfm

  Strength of Mechanism
    A scale for measuring the relative strength of a security mechanism

    - NIST CNSSI No. 4009 - https://www.cnss.gov/CNSS/issuances/Instructions.cfm

  transitive trust
    Also known as "Inductive Trust", in this process a Root of Trust gives a
    trustworthy description of a second group of functions. Based on this
    description, an interested entity can determine the trust it is to place in
    this second group of functions. If the interested entity determines that
    the trust level of the second group of functions is acceptable, the trust
    boundary is extended from the Root of Trust to include the second group of
    functions. In this case, the process can be iterated. The second group of
    functions can give a trustworthy description of the third group of
    functions, etc. Transitive trust is used to provide a trustworthy
    description of platform characteristics, and also to prove that
    non-migratable keys are in fact non-migratable.

    - TCG Glossary - https://trustedcomputinggroup.org/wp-content/uploads/TCG-Glossary-V1.1-Rev-1.0.pdf

  trust
    The confidence one element has in another that the second element will
    behave as expected`

    - NISTIR 8320A - https://nvlpubs.nist.gov/nistpubs/ir/2021/NIST.IR.8320A.pdf

  trust anchor
    An authoritative entity for which trust is assumed.

    - NIST SP 800-57 Part 1 Rev. 5 - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf

  trusted
    An element that another element relies upon to fulfill critical
    requirements on its behalf.

    - NISTIR 8320A - https://nvlpubs.nist.gov/nistpubs/ir/2021/NIST.IR.8320A.pdf

  trusted computing base (TCB)
    Totality of protection mechanisms within a computer system, including
    hardware, firmware, and software, the combination responsible for enforcing
    a security policy.

    - NIST CNSSI No. 4009 - https://www.cnss.gov/CNSS/issuances/Instructions.cfm

  trusted computer system
    A system that has the necessary security functions and assurance that the
    security policy will be enforced and that can process a range of
    information sensitivities (i.e. classified, controlled unclassified
    information (CUI), or unclassified public information) simultaneously.

    - NIST CNSSI No. 4009 - https://www.cnss.gov/CNSS/issuances/Instructions.cfm

  trustworthiness
    The attribute of a person or enterprise that provides confidence to others
    of the qualifications, capabilities, and reliability of that entity to
    perform specific tasks and fulfill assigned responsibilities.

    - NIST CNSSI No. 4009 - https://www.cnss.gov/CNSS/issuances/Instructions.cfm
