#[derive(Debug)]
pub enum Error {
    FailedToCreateEvaluationDomain,
    FailedToInverseFieldElement,
    FailedToCreateCosetOfEvaluationDomain,

    InvalidCommitmentLength(String),
    InvalidLagrangeBasisCommitments(String),
    InvalidQuotientPolynomialCommitments(String),
    InvalidStructuredReferenceStrings,
    InvalidNumberOfSegments(usize),
    InvalidNumberOfQueries(usize),
    InvalidSegmentIndex(usize),
    InvalidSegmentElementIndex(usize),
    InvalidSegmentSize(usize),
    InvalidEvaluationDomainSize(usize),
    InvalidPolynomialDegree(usize),
    InvalidGroupGenerator,

    SizeNotPowerOfTwo(usize),

    Pairing1Failed,
    Pairing2Failed,
    Pairing3Failed,
    Pairing4Failed,
    PointCheck1Failed,
    PointCheck2Failed,
    DegreeCheckFailed,

    // Caulk Sub-protocol
    FailedToDivideByVanishingPolynomial,
    RemainderAfterDivisionIsNonZero,
    FailedToCheckMultiUnity,
    MultiUnityPairingFailed,

    // Transcript
    FailedToSerializeElement,
}
