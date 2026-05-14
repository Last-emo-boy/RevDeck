use serde::Serialize;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DecodedInstruction {
    pub(crate) address: u64,
    pub(crate) size: usize,
    pub(crate) bytes: Vec<u8>,
    pub(crate) mnemonic: String,
    pub(crate) operands: String,
    pub(crate) typed_operands: Vec<DecodedOperand>,
    pub(crate) flow: InstructionFlow,
    pub(crate) target: Option<u64>,
    pub(crate) data_target: Option<u64>,
    pub(crate) confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DecodedOperand {
    pub(crate) role: OperandRole,
    pub(crate) kind: OperandKind,
    pub(crate) text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) register: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scale: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) displacement: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) effective_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) width_bits: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperandRole {
    Destination,
    Source,
    CallTarget,
    BranchTarget,
    DataReference,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperandKind {
    Register,
    RelativeTarget,
    Memory,
    Immediate,
    Raw,
}

impl DecodedOperand {
    fn raw(role: OperandRole, text: impl Into<String>) -> Self {
        Self {
            role,
            kind: OperandKind::Raw,
            text: text.into(),
            register: None,
            value: None,
            base: None,
            index: None,
            scale: None,
            displacement: None,
            effective_address: None,
            width_bits: None,
        }
    }

    fn register(role: OperandRole, name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            role,
            kind: OperandKind::Register,
            text: name.clone(),
            register: Some(name),
            value: None,
            base: None,
            index: None,
            scale: None,
            displacement: None,
            effective_address: None,
            width_bits: None,
        }
    }

    fn register_with_width(
        role: OperandRole,
        name: impl Into<String>,
        width_bits: Option<u16>,
    ) -> Self {
        let mut operand = Self::register(role, name);
        operand.width_bits = width_bits;
        operand
    }

    fn relative_target(role: OperandRole, address: u64) -> Self {
        Self {
            role,
            kind: OperandKind::RelativeTarget,
            text: format!("0x{address:016x}"),
            register: None,
            value: Some(address),
            base: None,
            index: None,
            scale: None,
            displacement: None,
            effective_address: None,
            width_bits: None,
        }
    }

    fn memory(role: OperandRole, memory: MemoryOperandSpec) -> Self {
        Self {
            role,
            kind: OperandKind::Memory,
            text: memory.text,
            register: None,
            value: None,
            base: memory.base,
            index: memory.index,
            scale: memory.scale,
            displacement: memory.displacement,
            effective_address: memory.effective_address,
            width_bits: memory.width_bits,
        }
    }

    fn immediate(role: OperandRole, value: u64, width_bits: Option<u16>) -> Self {
        Self {
            role,
            kind: OperandKind::Immediate,
            text: format!("0x{value:x}"),
            register: None,
            value: Some(value),
            base: None,
            index: None,
            scale: None,
            displacement: None,
            effective_address: None,
            width_bits,
        }
    }

    pub(crate) fn control_flow_target(&self) -> Option<u64> {
        if matches!(
            self.role,
            OperandRole::CallTarget | OperandRole::BranchTarget
        ) {
            self.value.or(self.effective_address)
        } else {
            None
        }
    }

    pub(crate) fn data_reference_target(&self) -> Option<u64> {
        if self.kind == OperandKind::Memory {
            self.effective_address
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemoryOperandSpec {
    text: String,
    base: Option<String>,
    index: Option<String>,
    scale: Option<u8>,
    displacement: Option<i64>,
    effective_address: Option<u64>,
    width_bits: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstructionFlow {
    None,
    Call,
    Jump,
    ConditionalBranch,
    Return,
}

impl InstructionFlow {
    pub(crate) fn as_kind(self) -> Option<&'static str> {
        match self {
            Self::Call => Some("call"),
            Self::Jump => Some("jump"),
            Self::ConditionalBranch => Some("conditional_branch"),
            Self::None | Self::Return => None,
        }
    }

    fn is_branch(self) -> bool {
        matches!(self, Self::Jump | Self::ConditionalBranch)
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Return | Self::Jump | Self::ConditionalBranch)
    }

    fn is_unconditional_terminal(self) -> bool {
        matches!(self, Self::Return | Self::Jump)
    }
}

impl DecodedInstruction {
    pub(crate) fn is_branch(&self) -> bool {
        self.flow.is_branch()
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.flow.is_terminal()
    }

    pub(crate) fn is_unconditional_terminal(&self) -> bool {
        self.flow.is_unconditional_terminal()
    }

    pub(crate) fn flow_kind(&self) -> Option<&'static str> {
        self.flow.as_kind()
    }
}

pub(crate) fn decode_native_instructions(
    start_address: u64,
    bytes: &[u8],
) -> Vec<DecodedInstruction> {
    let mut instructions = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let address = start_address + offset as u64;
        let opcode = bytes[offset];
        let mut instruction = match opcode {
            0x50..=0x57 => push_pop_register_instruction(
                address,
                &bytes[offset..],
                opcode - 0x50,
                "push",
                OperandRole::Source,
                0.65,
            ),
            0x58..=0x5f => push_pop_register_instruction(
                address,
                &bytes[offset..],
                opcode - 0x58,
                "pop",
                OperandRole::Destination,
                0.65,
            ),
            0x90 => simple_instruction(
                address,
                &bytes[offset..],
                1,
                "nop",
                "",
                InstructionFlow::None,
                0.7,
            ),
            0xc3 => simple_instruction(
                address,
                &bytes[offset..],
                1,
                "ret",
                "",
                InstructionFlow::Return,
                0.75,
            ),
            0xc2 if offset + 3 <= bytes.len() => {
                ret_immediate_instruction(address, &bytes[offset..])
            }
            0xc9 => simple_instruction(
                address,
                &bytes[offset..],
                1,
                "leave",
                "",
                InstructionFlow::None,
                0.68,
            ),
            0xcc => simple_instruction(
                address,
                &bytes[offset..],
                1,
                "int3",
                "",
                InstructionFlow::None,
                0.7,
            ),
            0xe8 if offset + 5 <= bytes.len() => rel32_instruction(
                address,
                &bytes[offset..],
                "call",
                InstructionFlow::Call,
                i32::from_le_bytes([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                ]),
            ),
            0xe9 if offset + 5 <= bytes.len() => rel32_instruction(
                address,
                &bytes[offset..],
                "jmp",
                InstructionFlow::Jump,
                i32::from_le_bytes([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                ]),
            ),
            0xeb if offset + 2 <= bytes.len() => rel8_instruction(
                address,
                &bytes[offset..],
                "jmp",
                InstructionFlow::Jump,
                bytes[offset + 1] as i8,
            ),
            0x66 if offset + 4 <= bytes.len()
                && (0x40..=0x47).contains(&bytes[offset + 1])
                && matches!(bytes[offset + 2], 0x89 | 0x8b) =>
            {
                let rex = RexPrefix::new(bytes[offset + 1]);
                decode_mov_rm16_r16(address, &bytes[offset..], 2, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        2,
                        "db",
                        "0x66",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x66 if offset + 3 <= bytes.len() && matches!(bytes[offset + 1], 0x89 | 0x8b) => {
                decode_mov_rm16_r16(address, &bytes[offset..], 1, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            2,
                            "db",
                            "0x66",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x66 if offset + 4 <= bytes.len() && bytes[offset + 1] == 0xc7 => {
                decode_mov_rm16_imm(address, &bytes[offset..]).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        2,
                        "db",
                        "0x66",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x6a if offset + 2 <= bytes.len() => push_immediate_instruction(
                address,
                &bytes[offset..],
                bytes[offset + 1] as i8 as i64 as u64,
                2,
                8,
            ),
            0x68 if offset + 5 <= bytes.len() => push_immediate_instruction(
                address,
                &bytes[offset..],
                i32::from_le_bytes([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                ]) as i64 as u64,
                5,
                32,
            ),
            0x8f if offset + 2 <= bytes.len() => {
                decode_pop_rm64(address, &bytes[offset..], 0, RexPrefix::default()).unwrap_or_else(
                    || {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x8f",
                            InstructionFlow::None,
                            0.35,
                        )
                    },
                )
            }
            0xb8..=0xbf if offset + 5 <= bytes.len() => {
                decode_mov_reg_imm32(address, &bytes[offset..], 0, 0)
            }
            0x40..=0x47
                if offset + 2 <= bytes.len() && (0x50..=0x5f).contains(&bytes[offset + 1]) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                let opcode = bytes[offset + 1];
                let (mnemonic, role, base_opcode) = if opcode <= 0x57 {
                    ("push", OperandRole::Source, 0x50)
                } else {
                    ("pop", OperandRole::Destination, 0x58)
                };
                push_pop_register_instruction(
                    address,
                    &bytes[offset..],
                    (opcode - base_opcode) | rex.b(),
                    mnemonic,
                    role,
                    0.65,
                )
            }
            0x40..=0x47 if offset + 3 <= bytes.len() && bytes[offset + 1] == 0x8f => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_pop_rm64(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex pop",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47
                if offset + 6 <= bytes.len() && (0xb8..=0xbf).contains(&bytes[offset + 1]) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_mov_reg_imm32(address, &bytes[offset..], 1, rex.b())
            }
            0x69 | 0x6b if offset + 3 <= bytes.len() => {
                decode_imul_r32_rm32_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47
                if offset + 4 <= bytes.len() && matches!(bytes[offset + 1], 0x69 | 0x6b) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_imul_r32_rm32_imm(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex imul",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x89 | 0x8b
                if offset + 2 <= bytes.len()
                    && !(opcode == 0x8b
                        && ModRm::parse(bytes[offset + 1]).mode == 0
                        && ModRm::parse(bytes[offset + 1]).rm == 0b101) =>
            {
                decode_mov_rm32_r32(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47
                if offset + 3 <= bytes.len()
                    && matches!(bytes[offset + 1], 0x89 | 0x8b)
                    && !(bytes[offset + 1] == 0x8b
                        && ModRm::parse(bytes[offset + 2]).mode == 0
                        && ModRm::parse(bytes[offset + 2]).rm == 0b101) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_mov_rm32_r32(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex mov",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x88 | 0x8a if offset + 2 <= bytes.len() => {
                decode_mov_rm8_r8(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x10 | 0x12 | 0x18 | 0x1a if offset + 2 <= bytes.len() => {
                decode_adc_sbb_rm8_r8(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x4f
                if offset + 3 <= bytes.len() && matches!(bytes[offset + 1], 0x88 | 0x8a) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_mov_rm8_r8(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex mov",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x4f
                if offset + 3 <= bytes.len()
                    && matches!(bytes[offset + 1], 0x10 | 0x12 | 0x18 | 0x1a) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_adc_sbb_rm8_r8(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex adc/sbb",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x38 | 0x3a if offset + 2 <= bytes.len() => {
                decode_cmp_rm8_r8(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x84 if offset + 2 <= bytes.len() => {
                decode_test_rm8_r8(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x84",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x4f
                if offset + 3 <= bytes.len() && matches!(bytes[offset + 1], 0x38 | 0x3a) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_cmp_rm8_r8(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex cmp",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x4f if offset + 3 <= bytes.len() && bytes[offset + 1] == 0x84 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_test_rm8_r8(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex test",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x80 if offset + 3 <= bytes.len() => {
                decode_group1_rm8_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    .or_else(|| {
                        decode_cmp_rm8_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    })
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x80",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0xf6 if offset + 2 <= bytes.len() => {
                decode_not_neg_rm8(address, &bytes[offset..], 0, RexPrefix::default())
                    .or_else(|| {
                        decode_test_rm8_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    })
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xf6",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x4f if offset + 4 <= bytes.len() && bytes[offset + 1] == 0x80 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_group1_rm8_imm(address, &bytes[offset..], 1, rex)
                    .or_else(|| decode_cmp_rm8_imm(address, &bytes[offset..], 1, rex))
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            3,
                            "db",
                            "rex imm",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x4f if offset + 3 <= bytes.len() && bytes[offset + 1] == 0xf6 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_not_neg_rm8(address, &bytes[offset..], 1, rex)
                    .or_else(|| decode_test_rm8_imm(address, &bytes[offset..], 1, rex))
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            3,
                            "db",
                            "rex f6",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x11 | 0x13 | 0x19 | 0x1b if offset + 2 <= bytes.len() => {
                decode_adc_sbb_rm32_r32(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47
                if offset + 3 <= bytes.len()
                    && matches!(bytes[offset + 1], 0x11 | 0x13 | 0x19 | 0x1b) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_adc_sbb_rm32_r32(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex adc/sbb",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x31 | 0x33 if offset + 2 <= bytes.len() => {
                decode_xor_rm32_r32(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47
                if offset + 3 <= bytes.len()
                    && matches!(bytes[offset + 1], 0x31 | 0x33)
                    && bytes[offset + 2] != 0x05 =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_xor_rm32_r32(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex xor",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x39 | 0x3b if offset + 2 <= bytes.len() => {
                decode_cmp_rm32_r32(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x85 if offset + 2 <= bytes.len() => {
                decode_test_rm32_r32(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x85",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47
                if offset + 3 <= bytes.len() && matches!(bytes[offset + 1], 0x39 | 0x3b) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_cmp_rm32_r32(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex cmp",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47 if offset + 3 <= bytes.len() && bytes[offset + 1] == 0x85 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_test_rm32_r32(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex test",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0xc6 if offset + 3 <= bytes.len() => {
                decode_mov_rm8_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xc6",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0xc7 if offset + 6 <= bytes.len() => {
                decode_mov_rm32_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xc7",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47 if offset + 4 <= bytes.len() && bytes[offset + 1] == 0xc6 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_mov_rm8_imm(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex mov",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47 if offset + 7 <= bytes.len() && bytes[offset + 1] == 0xc7 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_mov_rm32_imm(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex mov",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0xfe if offset + 2 <= bytes.len() => {
                decode_inc_dec_rm8(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xfe",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x4f if offset + 3 <= bytes.len() && bytes[offset + 1] == 0xfe => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_inc_dec_rm8(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex fe",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0xf7 if offset + 2 <= bytes.len() => {
                decode_not_neg_rm32(address, &bytes[offset..], 0, RexPrefix::default())
                    .or_else(|| {
                        decode_test_rm32_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    })
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xf7",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47 if offset + 3 <= bytes.len() && bytes[offset + 1] == 0xf7 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_not_neg_rm32(address, &bytes[offset..], 1, rex)
                    .or_else(|| decode_test_rm32_imm(address, &bytes[offset..], 1, rex))
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            3,
                            "db",
                            "rex f7",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47 if offset + 3 <= bytes.len() && bytes[offset + 1] == 0xf7 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_test_rm32_imm(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex test",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47
                if offset + 4 <= bytes.len() && matches!(bytes[offset + 1], 0x81 | 0x83) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_group1_rm32_imm(address, &bytes[offset..], 1, rex)
                    .or_else(|| decode_cmp_rm32_imm(address, &bytes[offset..], 1, rex))
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            3,
                            "db",
                            "rex imm",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47 if offset + 4 <= bytes.len() && bytes[offset + 1] == 0xc1 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_shift_rm32_imm(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex shift",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47
                if offset + 3 <= bytes.len() && matches!(bytes[offset + 1], 0xd1 | 0xd3) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                let count = if bytes[offset + 1] == 0xd1 {
                    ShiftCountOperand::One
                } else {
                    ShiftCountOperand::Cl
                };
                decode_shift_rm32_count(address, &bytes[offset..], 1, rex, count).unwrap_or_else(
                    || {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            3,
                            "db",
                            "rex shift",
                            InstructionFlow::None,
                            0.35,
                        )
                    },
                )
            }
            0xc0 if offset + 3 <= bytes.len() => {
                decode_shift_rm8_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xc0",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0xd0 | 0xd2 if offset + 2 <= bytes.len() => {
                let count = if opcode == 0xd0 {
                    ShiftCountOperand::One
                } else {
                    ShiftCountOperand::Cl
                };
                decode_shift_rm8_count(address, &bytes[offset..], 0, RexPrefix::default(), count)
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x4f if offset + 4 <= bytes.len() && bytes[offset + 1] == 0xc0 => {
                let rex = RexPrefix::new(bytes[offset]);
                decode_shift_rm8_imm(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex shift",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x4f
                if offset + 3 <= bytes.len() && matches!(bytes[offset + 1], 0xd0 | 0xd2) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                let count = if bytes[offset + 1] == 0xd0 {
                    ShiftCountOperand::One
                } else {
                    ShiftCountOperand::Cl
                };
                decode_shift_rm8_count(address, &bytes[offset..], 1, rex, count).unwrap_or_else(
                    || {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            3,
                            "db",
                            "rex shift",
                            InstructionFlow::None,
                            0.35,
                        )
                    },
                )
            }
            0x81 | 0x83 if offset + 3 <= bytes.len() => {
                decode_group1_rm32_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    .or_else(|| {
                        decode_cmp_rm32_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    })
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0xc1 if offset + 3 <= bytes.len() => {
                decode_shift_rm32_imm(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xc1",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0xd1 | 0xd3 if offset + 2 <= bytes.len() => {
                let count = if opcode == 0xd1 {
                    ShiftCountOperand::One
                } else {
                    ShiftCountOperand::Cl
                };
                decode_shift_rm32_count(address, &bytes[offset..], 0, RexPrefix::default(), count)
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            format!("0x{opcode:02x}"),
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x8d if offset + 2 <= bytes.len() => {
                decode_lea_rm(address, &bytes[offset..], 0, RexPrefix::default(), 32)
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x8d",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x70..=0x7f if offset + 2 <= bytes.len() => rel8_instruction(
                address,
                &bytes[offset..],
                jcc_mnemonic(opcode),
                InstructionFlow::ConditionalBranch,
                bytes[offset + 1] as i8,
            ),
            0x0f if offset + 6 <= bytes.len() && (0x80..=0x8f).contains(&bytes[offset + 1]) => {
                rel32_instruction(
                    address,
                    &bytes[offset..],
                    jcc_mnemonic(bytes[offset + 1] - 0x10),
                    InstructionFlow::ConditionalBranch,
                    i32::from_le_bytes([
                        bytes[offset + 2],
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                    ]),
                )
            }
            0x0f if offset + 3 <= bytes.len() && (0x40..=0x4f).contains(&bytes[offset + 1]) => {
                decode_cmovcc_r32_rm32(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x0f",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x0f if offset + 3 <= bytes.len() && (0x90..=0x9f).contains(&bytes[offset + 1]) => {
                decode_setcc_rm8(address, &bytes[offset..], 0, RexPrefix::default()).unwrap_or_else(
                    || {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x0f",
                            InstructionFlow::None,
                            0.35,
                        )
                    },
                )
            }
            0x0f if offset + 3 <= bytes.len() && matches!(bytes[offset + 1], 0xb6 | 0xb7) => {
                decode_movzx_r32_rm(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x0f",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x0f if offset + 3 <= bytes.len() && matches!(bytes[offset + 1], 0xbe | 0xbf) => {
                decode_movsx_r32_rm(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0x0f",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x40..=0x47
                if offset + 4 <= bytes.len()
                    && bytes[offset + 1] == 0x0f
                    && (0x40..=0x4f).contains(&bytes[offset + 2]) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_cmovcc_r32_rm32(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        4,
                        "db",
                        "rex cmov",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47
                if offset + 4 <= bytes.len()
                    && bytes[offset + 1] == 0x0f
                    && (0x90..=0x9f).contains(&bytes[offset + 2]) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_setcc_rm8(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        4,
                        "db",
                        "rex set",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47
                if offset + 4 <= bytes.len()
                    && bytes[offset + 1] == 0x0f
                    && matches!(bytes[offset + 2], 0xb6 | 0xb7) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_movzx_r32_rm(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        4,
                        "db",
                        "rex movzx",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47
                if offset + 4 <= bytes.len()
                    && bytes[offset + 1] == 0x0f
                    && matches!(bytes[offset + 2], 0xbe | 0xbf) =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_movsx_r32_rm(address, &bytes[offset..], 1, rex).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        4,
                        "db",
                        "rex movsx",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0xff if offset + 6 <= bytes.len() && bytes[offset + 1] == 0x15 => {
                rip_relative_instruction(
                    address,
                    &bytes[offset..],
                    6,
                    i32::from_le_bytes([
                        bytes[offset + 2],
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                    ]),
                    RipRelativeSpec::indirect_flow("call", InstructionFlow::Call),
                )
            }
            0xff if offset + 6 <= bytes.len() && bytes[offset + 1] == 0x25 => {
                rip_relative_instruction(
                    address,
                    &bytes[offset..],
                    6,
                    i32::from_le_bytes([
                        bytes[offset + 2],
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                    ]),
                    RipRelativeSpec::indirect_flow("jmp", InstructionFlow::Jump),
                )
            }
            0xff if offset + 2 <= bytes.len()
                && matches!(ModRm::parse(bytes[offset + 1]).reg, 0 | 1) =>
            {
                decode_inc_dec_rm32(address, &bytes[offset..], 0, RexPrefix::default())
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xff",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0xff if offset + 2 <= bytes.len() => {
                decode_ff_group_instruction(address, &bytes[offset..], RexPrefix::default(), 1)
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            1,
                            "db",
                            "0xff",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x48 if offset + 3 <= bytes.len()
                && bytes[offset + 1] == 0x89
                && bytes[offset + 2] == 0xe5 =>
            {
                register_move_instruction(address, &bytes[offset..], "rbp", "rsp", 0.7)
            }
            0x48 if offset + 4 <= bytes.len()
                && bytes[offset + 1] == 0x83
                && bytes[offset + 2] == 0xec =>
            {
                stack_pointer_immediate_instruction(
                    address,
                    &bytes[offset..],
                    4,
                    "sub",
                    bytes[offset + 3] as u64,
                    8,
                )
            }
            0x48 if offset + 7 <= bytes.len()
                && bytes[offset + 1] == 0x81
                && bytes[offset + 2] == 0xec =>
            {
                stack_pointer_immediate_instruction(
                    address,
                    &bytes[offset..],
                    7,
                    "sub",
                    u32::from_le_bytes([
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                    ]) as u64,
                    32,
                )
            }
            0x48 if offset + 4 <= bytes.len()
                && bytes[offset + 1] == 0x83
                && bytes[offset + 2] == 0xc4 =>
            {
                stack_pointer_immediate_instruction(
                    address,
                    &bytes[offset..],
                    4,
                    "add",
                    bytes[offset + 3] as u64,
                    8,
                )
            }
            0x48 if offset + 7 <= bytes.len()
                && bytes[offset + 1] == 0x81
                && bytes[offset + 2] == 0xc4 =>
            {
                stack_pointer_immediate_instruction(
                    address,
                    &bytes[offset..],
                    7,
                    "add",
                    u32::from_le_bytes([
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                    ]) as u64,
                    32,
                )
            }
            0x48..=0x4f
                if offset + 7 <= bytes.len()
                    && bytes[offset + 1] == 0x8d
                    && (bytes[offset + 2] & 0b1100_0111) == 0x05 =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                let modrm = ModRm::parse(bytes[offset + 2]);
                rip_relative_instruction(
                    address,
                    &bytes[offset..],
                    7,
                    i32::from_le_bytes([
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                    ]),
                    RipRelativeSpec::data_reference("lea", Some(64), gpr64(modrm.reg | rex.r())),
                )
            }
            0x48..=0x4f
                if offset + 7 <= bytes.len()
                    && bytes[offset + 1] == 0x8b
                    && (bytes[offset + 2] & 0b1100_0111) == 0x05 =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                let modrm = ModRm::parse(bytes[offset + 2]);
                rip_relative_instruction(
                    address,
                    &bytes[offset..],
                    7,
                    i32::from_le_bytes([
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                    ]),
                    RipRelativeSpec::data_reference("mov", Some(64), gpr64(modrm.reg | rex.r())),
                )
            }
            0x8d if offset + 6 <= bytes.len() && (bytes[offset + 1] & 0b1100_0111) == 0x05 => {
                let modrm = ModRm::parse(bytes[offset + 1]);
                rip_relative_instruction(
                    address,
                    &bytes[offset..],
                    6,
                    i32::from_le_bytes([
                        bytes[offset + 2],
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                    ]),
                    RipRelativeSpec::data_reference("lea", Some(32), gpr32(modrm.reg)),
                )
            }
            0x8b if offset + 6 <= bytes.len() && (bytes[offset + 1] & 0b1100_0111) == 0x05 => {
                let modrm = ModRm::parse(bytes[offset + 1]);
                rip_relative_instruction(
                    address,
                    &bytes[offset..],
                    6,
                    i32::from_le_bytes([
                        bytes[offset + 2],
                        bytes[offset + 3],
                        bytes[offset + 4],
                        bytes[offset + 5],
                    ]),
                    RipRelativeSpec::data_reference("mov", Some(32), gpr32(modrm.reg)),
                )
            }
            0x40..=0x47
                if offset + 3 <= bytes.len()
                    && bytes[offset + 1] == 0x8d
                    && bytes[offset + 2] != 0x05 =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_lea_rm(address, &bytes[offset..], 1, rex, 32).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex lea",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x40..=0x47
                if offset + 3 <= bytes.len()
                    && bytes[offset + 1] == 0xff
                    && bytes[offset + 2] != 0x05 =>
            {
                let rex = RexPrefix::new(bytes[offset]);
                decode_inc_dec_rm32(address, &bytes[offset..], 1, rex)
                    .or_else(|| decode_ff_group_instruction(address, &bytes[offset..], rex, 2))
                    .unwrap_or_else(|| {
                        simple_instruction(
                            address,
                            &bytes[offset..],
                            3,
                            "db",
                            "rex ff",
                            InstructionFlow::None,
                            0.35,
                        )
                    })
            }
            0x48..=0x4f
                if offset + 3 <= bytes.len()
                    && bytes[offset + 1] == 0xff
                    && bytes[offset + 2] != 0x05 =>
            {
                decode_rex_w_instruction(address, &bytes[offset..]).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        "db",
                        "rex ff",
                        InstructionFlow::None,
                        0.35,
                    )
                })
            }
            0x48..=0x4f
                if offset + 3 <= bytes.len() && (0xb8..=0xbf).contains(&bytes[offset + 1]) =>
            {
                decode_rex_w_instruction(address, &bytes[offset..]).unwrap_or_else(|| {
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        2,
                        "mov",
                        "r64,imm",
                        InstructionFlow::None,
                        0.55,
                    )
                })
            }
            0x48..=0x4f
                if offset + 3 <= bytes.len()
                    && matches!(
                        bytes[offset + 1],
                        0x11 | 0x13
                            | 0x19
                            | 0x1b
                            | 0x31
                            | 0x33
                            | 0x39
                            | 0x3b
                            | 0x63
                            | 0x81
                            | 0x83
                            | 0x85
                            | 0x89
                            | 0x8b
                            | 0x8d
                            | 0xc7
                            | 0xf7
                    )
                    && bytes[offset + 2] != 0x05 =>
            {
                decode_rex_w_instruction(address, &bytes[offset..]).unwrap_or_else(|| {
                    let mnemonic = match bytes[offset + 1] {
                        0x11 | 0x13 => "adc",
                        0x19 | 0x1b => "sbb",
                        0x31 | 0x33 => "xor",
                        0x39 | 0x3b | 0x81 | 0x83 => "cmp",
                        0x85 | 0xf7 => "test",
                        0x63 => "movsxd",
                        0x8d => "lea",
                        _ => "mov",
                    };
                    simple_instruction(
                        address,
                        &bytes[offset..],
                        3,
                        mnemonic,
                        "r/m64,r64",
                        InstructionFlow::None,
                        0.55,
                    )
                })
            }
            _ => simple_instruction(
                address,
                &bytes[offset..],
                1,
                "db",
                format!("0x{opcode:02x}"),
                InstructionFlow::None,
                0.35,
            ),
        };
        if offset + instruction.size > bytes.len() {
            instruction.size = bytes.len() - offset;
            instruction.bytes = bytes[offset..].to_vec();
        }
        offset += instruction.size.max(1);
        instructions.push(instruction);
    }
    instructions
}

fn simple_instruction(
    address: u64,
    remaining: &[u8],
    size: usize,
    mnemonic: impl Into<String>,
    operands: impl Into<String>,
    flow: InstructionFlow,
    confidence: f64,
) -> DecodedInstruction {
    let size = size.min(remaining.len());
    let operands = operands.into();
    DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.into(),
        typed_operands: raw_operands(&operands),
        operands,
        flow,
        target: None,
        data_target: None,
        confidence,
    }
}

fn rel32_instruction(
    address: u64,
    remaining: &[u8],
    mnemonic: impl Into<String>,
    flow: InstructionFlow,
    displacement: i32,
) -> DecodedInstruction {
    let target = relative_target(address, 5, displacement as i64);
    let typed_operands = vec![DecodedOperand::relative_target(
        control_operand_role(flow),
        target,
    )];
    DecodedInstruction {
        address,
        size: 5,
        bytes: remaining[..5].to_vec(),
        mnemonic: mnemonic.into(),
        operands: format!("0x{target:016x}"),
        typed_operands,
        flow,
        target: Some(target),
        data_target: None,
        confidence: 0.65,
    }
}

fn rel8_instruction(
    address: u64,
    remaining: &[u8],
    mnemonic: impl Into<String>,
    flow: InstructionFlow,
    displacement: i8,
) -> DecodedInstruction {
    let target = relative_target(address, 2, displacement as i64);
    let typed_operands = vec![DecodedOperand::relative_target(
        control_operand_role(flow),
        target,
    )];
    DecodedInstruction {
        address,
        size: 2,
        bytes: remaining[..2].to_vec(),
        mnemonic: mnemonic.into(),
        operands: format!("0x{target:016x}"),
        typed_operands,
        flow,
        target: Some(target),
        data_target: None,
        confidence: 0.65,
    }
}

fn register_move_instruction(
    address: u64,
    remaining: &[u8],
    destination: &'static str,
    source: &'static str,
    confidence: f64,
) -> DecodedInstruction {
    let typed_operands = vec![
        DecodedOperand::register(OperandRole::Destination, destination),
        DecodedOperand::register(OperandRole::Source, source),
    ];
    DecodedInstruction {
        address,
        size: 3,
        bytes: remaining[..3].to_vec(),
        mnemonic: "mov".to_string(),
        operands: format!("{destination},{source}"),
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence,
    }
}

fn push_pop_register_instruction(
    address: u64,
    remaining: &[u8],
    register_index: u8,
    mnemonic: &'static str,
    role: OperandRole,
    confidence: f64,
) -> DecodedInstruction {
    let register = gpr64(register_index);
    let typed_operands = vec![DecodedOperand::register(role, register)];
    let size = if remaining
        .first()
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        2
    } else {
        1
    };
    DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands: register.to_string(),
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence,
    }
}

fn push_immediate_instruction(
    address: u64,
    remaining: &[u8],
    value: u64,
    size: usize,
    immediate_width_bits: u16,
) -> DecodedInstruction {
    let typed_operands = vec![DecodedOperand::immediate(
        OperandRole::Source,
        value,
        Some(immediate_width_bits),
    )];
    DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "push".to_string(),
        operands: format!("0x{value:x}"),
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.62,
    }
}

fn ret_immediate_instruction(address: u64, remaining: &[u8]) -> DecodedInstruction {
    let value = u16::from_le_bytes([remaining[1], remaining[2]]) as u64;
    let typed_operands = vec![DecodedOperand::immediate(
        OperandRole::Source,
        value,
        Some(16),
    )];
    DecodedInstruction {
        address,
        size: 3,
        bytes: remaining[..3].to_vec(),
        mnemonic: "ret".to_string(),
        operands: format!("0x{value:x}"),
        typed_operands,
        flow: InstructionFlow::Return,
        target: None,
        data_target: None,
        confidence: 0.72,
    }
}

fn stack_pointer_immediate_instruction(
    address: u64,
    remaining: &[u8],
    size: usize,
    mnemonic: &'static str,
    value: u64,
    immediate_width_bits: u16,
) -> DecodedInstruction {
    let typed_operands = vec![
        DecodedOperand::register(OperandRole::Destination, "rsp"),
        DecodedOperand::immediate(OperandRole::Source, value, Some(immediate_width_bits)),
    ];
    DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands: format!("rsp,0x{value:x}"),
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.7,
    }
}

#[derive(Debug, Clone, Copy)]
struct RipRelativeSpec {
    mnemonic: &'static str,
    operand_template: &'static str,
    memory_template: &'static str,
    flow: InstructionFlow,
    memory_role: OperandRole,
    width_bits: Option<u16>,
    destination_register: Option<&'static str>,
    destination_width_bits: Option<u16>,
}

impl RipRelativeSpec {
    fn indirect_flow(mnemonic: &'static str, flow: InstructionFlow) -> Self {
        Self {
            mnemonic,
            operand_template: "qword ptr [rip+disp32]",
            memory_template: "qword ptr [rip+disp32]",
            flow,
            memory_role: control_operand_role(flow),
            width_bits: Some(64),
            destination_register: None,
            destination_width_bits: None,
        }
    }

    fn data_reference(
        mnemonic: &'static str,
        width_bits: Option<u16>,
        destination_register: &'static str,
    ) -> Self {
        Self {
            mnemonic,
            operand_template: "reg,[rip+disp32]",
            memory_template: "[rip+disp32]",
            flow: InstructionFlow::None,
            memory_role: OperandRole::DataReference,
            width_bits,
            destination_register: Some(destination_register),
            destination_width_bits: width_bits,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegRmDirection {
    RegToRm,
    RmToReg,
}

#[derive(Debug, Clone, Copy)]
struct RegRmInstructionSpec {
    mnemonic: &'static str,
    direction: RegRmDirection,
    mutates_destination: bool,
    confidence: f64,
}

#[derive(Debug, Clone, Copy)]
struct ImmRmInstructionSpec {
    mnemonic: &'static str,
    modrm_reg: u8,
    immediate_width_bits: u16,
    immediate_size: usize,
    confidence: f64,
}

#[derive(Debug, Clone, Copy)]
struct ModRm {
    mode: u8,
    reg: u8,
    rm: u8,
}

impl ModRm {
    fn parse(byte: u8) -> Self {
        Self {
            mode: byte >> 6,
            reg: (byte >> 3) & 0x07,
            rm: byte & 0x07,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RexPrefix {
    byte: u8,
    present: bool,
}

impl Default for RexPrefix {
    fn default() -> Self {
        Self {
            byte: 0x40,
            present: false,
        }
    }
}

impl RexPrefix {
    fn new(byte: u8) -> Self {
        Self {
            byte,
            present: true,
        }
    }

    fn b(self) -> u8 {
        (self.byte & 0x01) << 3
    }

    fn x(self) -> u8 {
        (self.byte & 0x02) << 2
    }

    fn r(self) -> u8 {
        (self.byte & 0x04) << 1
    }

    fn present(self) -> bool {
        self.present
    }
}

fn decode_rex_w_instruction(address: u64, remaining: &[u8]) -> Option<DecodedInstruction> {
    let rex = RexPrefix::new(*remaining.first()?);
    let opcode = *remaining.get(1)?;
    match opcode {
        0xb8..=0xbf => decode_rex_w_mov_reg_imm64(address, remaining, rex),
        0x63 => decode_movsxd_r64_rm32(address, remaining, rex),
        0x8d => decode_lea_rm(address, remaining, 1, rex, 64),
        0x81 | 0x83 | 0xc7 | 0xf7 => decode_rex_w_rm_imm(address, remaining, rex),
        0xff => decode_ff_group_instruction(address, remaining, rex, 2),
        _ => decode_rex_w_reg_rm(address, remaining, rex),
    }
}

fn decode_mov_rm32_r32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let direction = match opcode {
        0x89 => RegRmDirection::RegToRm,
        0x8b => RegRmDirection::RmToReg,
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let register = DecodedOperand::register_with_width(
        register_role(direction, true),
        gpr32(modrm.reg | rex.r()),
        Some(32),
    );
    let (rm_operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                memory_role(direction, true),
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(memory_role(direction, true), memory.spec),
            memory.size,
        )
    };
    let typed_operands = match direction {
        RegRmDirection::RegToRm => vec![rm_operand, register],
        RegRmDirection::RmToReg => vec![register, rm_operand],
    };
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "mov".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.6,
    })
}

fn decode_mov_rm8_r8(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let direction = match opcode {
        0x88 => RegRmDirection::RegToRm,
        0x8a => RegRmDirection::RmToReg,
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let register = DecodedOperand::register_with_width(
        register_role(direction, true),
        gpr8(modrm.reg | rex.r(), rex.present()),
        Some(8),
    );
    let (rm_operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                memory_role(direction, true),
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(8))?;
        (
            DecodedOperand::memory(memory_role(direction, true), memory.spec),
            memory.size,
        )
    };
    let typed_operands = match direction {
        RegRmDirection::RegToRm => vec![rm_operand, register],
        RegRmDirection::RmToReg => vec![register, rm_operand],
    };
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "mov".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_adc_sbb_rm8_r8(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let (mnemonic, direction) = match opcode {
        0x10 => ("adc", RegRmDirection::RegToRm),
        0x12 => ("adc", RegRmDirection::RmToReg),
        0x18 => ("sbb", RegRmDirection::RegToRm),
        0x1a => ("sbb", RegRmDirection::RmToReg),
        _ => return None,
    };
    decode_rm8_r8_instruction(
        address,
        remaining,
        opcode_offset,
        rex,
        RegRmInstructionSpec {
            mnemonic,
            direction,
            mutates_destination: true,
            confidence: 0.58,
        },
    )
}

fn decode_cmp_rm8_r8(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let direction = match opcode {
        0x38 => RegRmDirection::RegToRm,
        0x3a => RegRmDirection::RmToReg,
        _ => return None,
    };
    decode_rm8_r8_instruction(
        address,
        remaining,
        opcode_offset,
        rex,
        RegRmInstructionSpec {
            mnemonic: "cmp",
            direction,
            mutates_destination: false,
            confidence: 0.58,
        },
    )
}

fn decode_test_rm8_r8(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x84 {
        return None;
    }
    decode_rm8_r8_instruction(
        address,
        remaining,
        opcode_offset,
        rex,
        RegRmInstructionSpec {
            mnemonic: "test",
            direction: RegRmDirection::RegToRm,
            mutates_destination: false,
            confidence: 0.58,
        },
    )
}

fn decode_rm8_r8_instruction(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
    spec: RegRmInstructionSpec,
) -> Option<DecodedInstruction> {
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let register = DecodedOperand::register_with_width(
        register_role(spec.direction, spec.mutates_destination),
        gpr8(modrm.reg | rex.r(), rex.present()),
        Some(8),
    );
    let (rm_operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                memory_role(spec.direction, spec.mutates_destination),
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(8))?;
        (
            DecodedOperand::memory(
                memory_role(spec.direction, spec.mutates_destination),
                memory.spec,
            ),
            memory.size,
        )
    };
    let typed_operands = match spec.direction {
        RegRmDirection::RegToRm => vec![rm_operand, register],
        RegRmDirection::RmToReg => vec![register, rm_operand],
    };
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: spec.mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: spec.confidence,
    })
}

fn decode_cmp_rm8_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    decode_rm8_imm_instruction(
        address,
        remaining,
        opcode_offset,
        rex,
        ImmRmInstructionSpec {
            mnemonic: "cmp",
            modrm_reg: 7,
            immediate_width_bits: 8,
            immediate_size: 1,
            confidence: 0.58,
        },
    )
}

fn decode_test_rm8_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    decode_rm8_imm_instruction(
        address,
        remaining,
        opcode_offset,
        rex,
        ImmRmInstructionSpec {
            mnemonic: "test",
            modrm_reg: 0,
            immediate_width_bits: 8,
            immediate_size: 1,
            confidence: 0.58,
        },
    )
}

fn decode_group1_rm8_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x80 {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let mnemonic = match modrm.reg {
        0 => "add",
        1 => "or",
        2 => "adc",
        3 => "sbb",
        4 => "and",
        5 => "sub",
        6 => "xor",
        _ => return None,
    };
    let (destination, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(8))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let immediate = *remaining.get(immediate_offset)? as u64;
    let immediate_end = immediate_offset + 1;
    let typed_operands = vec![
        destination,
        DecodedOperand::immediate(OperandRole::Source, immediate, Some(8)),
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_rm8_imm_instruction(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
    spec: ImmRmInstructionSpec,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    if !matches!(opcode, 0x80 | 0xf6) {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.reg != spec.modrm_reg {
        return None;
    }
    let (rm_operand, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Source,
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(8))?;
        (
            DecodedOperand::memory(OperandRole::Source, memory.spec),
            memory.size,
        )
    };
    let immediate = *remaining.get(immediate_offset)? as u64;
    let immediate_end = immediate_offset + spec.immediate_size;
    let typed_operands = vec![
        rm_operand,
        DecodedOperand::immediate(
            OperandRole::Source,
            immediate,
            Some(spec.immediate_width_bits),
        ),
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: spec.mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: spec.confidence,
    })
}

fn decode_mov_rm16_r16(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.first()? != 0x66 {
        return None;
    }
    let opcode = *remaining.get(opcode_offset)?;
    let direction = match opcode {
        0x89 => RegRmDirection::RegToRm,
        0x8b => RegRmDirection::RmToReg,
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let register = DecodedOperand::register_with_width(
        register_role(direction, true),
        gpr16(modrm.reg | rex.r()),
        Some(16),
    );
    let (rm_operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                memory_role(direction, true),
                gpr16(modrm.rm | rex.b()),
                Some(16),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(16))?;
        (
            DecodedOperand::memory(memory_role(direction, true), memory.spec),
            memory.size,
        )
    };
    let typed_operands = match direction {
        RegRmDirection::RegToRm => vec![rm_operand, register],
        RegRmDirection::RmToReg => vec![register, rm_operand],
    };
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "mov".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_xor_rm32_r32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let direction = match opcode {
        0x31 => RegRmDirection::RegToRm,
        0x33 => RegRmDirection::RmToReg,
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.mode != 0b11 {
        return None;
    }
    let rm = DecodedOperand::register_with_width(
        memory_role(direction, true),
        gpr32(modrm.rm | rex.b()),
        Some(32),
    );
    let reg = DecodedOperand::register_with_width(
        register_role(direction, true),
        gpr32(modrm.reg | rex.r()),
        Some(32),
    );
    let typed_operands = match direction {
        RegRmDirection::RegToRm => vec![rm, reg],
        RegRmDirection::RmToReg => vec![reg, rm],
    };
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: opcode_offset + 2,
        bytes: remaining[..opcode_offset + 2].to_vec(),
        mnemonic: "xor".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_imul_r32_rm32_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let (immediate_width_bits, immediate_size) = match opcode {
        0x69 => (32, 4),
        0x6b => (8, 1),
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.mode != 0b11 {
        return None;
    }
    let immediate_offset = opcode_offset + 2;
    let immediate_end = immediate_offset + immediate_size;
    let immediate = match immediate_size {
        1 => *remaining.get(immediate_offset)? as i8 as i64 as u64,
        4 => read_i32(remaining, immediate_offset)? as i64 as u64,
        _ => return None,
    };
    let destination = gpr32(modrm.reg | rex.r());
    let source = gpr32(modrm.rm | rex.b());
    let typed_operands = vec![
        DecodedOperand::register_with_width(OperandRole::Destination, destination, Some(32)),
        DecodedOperand::register_with_width(OperandRole::Source, source, Some(32)),
        DecodedOperand::immediate(OperandRole::Source, immediate, Some(immediate_width_bits)),
    ];
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: "imul".to_string(),
        operands: format!("{destination},{source},0x{immediate:x}"),
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_cmovcc_r32_rm32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x0f {
        return None;
    }
    let opcode = *remaining.get(opcode_offset + 1)?;
    if !(0x40..=0x4f).contains(&opcode) {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 2)?);
    let mnemonic = format!("cmov{}", cmovcc_suffix(opcode));
    let destination = gpr32(modrm.reg | rex.r());
    let (source, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Source,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 3,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 3, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Source, memory.spec),
            memory.size,
        )
    };
    let typed_operands = vec![
        DecodedOperand::register_with_width(OperandRole::Destination, destination, Some(32)),
        source,
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic,
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_setcc_rm8(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x0f {
        return None;
    }
    let opcode = *remaining.get(opcode_offset + 1)?;
    if !(0x90..=0x9f).contains(&opcode) {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 2)?);
    let mnemonic = format!("set{}", cmovcc_suffix(opcode));
    let (operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 3,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 3, Some(8))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let operands = operand.text.clone();
    let typed_operands = vec![operand];
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic,
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_movzx_r32_rm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x0f {
        return None;
    }
    let source_width_bits = match *remaining.get(opcode_offset + 1)? {
        0xb6 => 8,
        0xb7 => 16,
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 2)?);
    let destination = gpr32(modrm.reg | rex.r());
    let (source, size) = if modrm.mode == 0b11 {
        let source = match source_width_bits {
            8 => gpr8(modrm.rm | rex.b(), rex.present()),
            16 => gpr16(modrm.rm | rex.b()),
            _ => return None,
        };
        (
            DecodedOperand::register_with_width(
                OperandRole::Source,
                source,
                Some(source_width_bits),
            ),
            opcode_offset + 3,
        )
    } else {
        let memory = decode_memory_operand(
            address,
            remaining,
            rex,
            modrm,
            opcode_offset + 3,
            Some(source_width_bits),
        )?;
        (
            DecodedOperand::memory(OperandRole::Source, memory.spec),
            memory.size,
        )
    };
    let typed_operands = vec![
        DecodedOperand::register_with_width(OperandRole::Destination, destination, Some(32)),
        source,
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "movzx".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_movsx_r32_rm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x0f {
        return None;
    }
    let source_width_bits = match *remaining.get(opcode_offset + 1)? {
        0xbe => 8,
        0xbf => 16,
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 2)?);
    let destination = gpr32(modrm.reg | rex.r());
    let (source, size) = if modrm.mode == 0b11 {
        let source = match source_width_bits {
            8 => gpr8(modrm.rm | rex.b(), rex.present()),
            16 => gpr16(modrm.rm | rex.b()),
            _ => return None,
        };
        (
            DecodedOperand::register_with_width(
                OperandRole::Source,
                source,
                Some(source_width_bits),
            ),
            opcode_offset + 3,
        )
    } else {
        let memory = decode_memory_operand(
            address,
            remaining,
            rex,
            modrm,
            opcode_offset + 3,
            Some(source_width_bits),
        )?;
        (
            DecodedOperand::memory(OperandRole::Source, memory.spec),
            memory.size,
        )
    };
    let typed_operands = vec![
        DecodedOperand::register_with_width(OperandRole::Destination, destination, Some(32)),
        source,
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "movsx".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_cmp_rm32_r32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let direction = match opcode {
        0x39 => RegRmDirection::RegToRm,
        0x3b => RegRmDirection::RmToReg,
        _ => return None,
    };
    decode_rm32_r32_instruction(
        address,
        remaining,
        opcode_offset,
        rex,
        RegRmInstructionSpec {
            mnemonic: "cmp",
            direction,
            mutates_destination: false,
            confidence: 0.58,
        },
    )
}

fn decode_rm32_r32_instruction(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
    spec: RegRmInstructionSpec,
) -> Option<DecodedInstruction> {
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let reg = DecodedOperand::register_with_width(
        register_role(spec.direction, spec.mutates_destination),
        gpr32(modrm.reg | rex.r()),
        Some(32),
    );
    let (rm, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                memory_role(spec.direction, spec.mutates_destination),
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(
                memory_role(spec.direction, spec.mutates_destination),
                memory.spec,
            ),
            memory.size,
        )
    };
    let typed_operands = match spec.direction {
        RegRmDirection::RegToRm => vec![rm, reg],
        RegRmDirection::RmToReg => vec![reg, rm],
    };
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: spec.mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: spec.confidence,
    })
}

fn decode_adc_sbb_rm32_r32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let (mnemonic, direction) = match opcode {
        0x11 => ("adc", RegRmDirection::RegToRm),
        0x13 => ("adc", RegRmDirection::RmToReg),
        0x19 => ("sbb", RegRmDirection::RegToRm),
        0x1b => ("sbb", RegRmDirection::RmToReg),
        _ => return None,
    };
    decode_rm32_r32_instruction(
        address,
        remaining,
        opcode_offset,
        rex,
        RegRmInstructionSpec {
            mnemonic,
            direction,
            mutates_destination: true,
            confidence: 0.58,
        },
    )
}

fn decode_cmp_rm32_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let spec = match opcode {
        0x81 => ImmRmInstructionSpec {
            mnemonic: "cmp",
            modrm_reg: 7,
            immediate_width_bits: 32,
            immediate_size: 4,
            confidence: 0.58,
        },
        0x83 => ImmRmInstructionSpec {
            mnemonic: "cmp",
            modrm_reg: 7,
            immediate_width_bits: 8,
            immediate_size: 1,
            confidence: 0.58,
        },
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.reg != spec.modrm_reg {
        return None;
    }
    let (rm_operand, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Source,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Source, memory.spec),
            memory.size,
        )
    };
    let immediate_end = immediate_offset + spec.immediate_size;
    let immediate = match spec.immediate_size {
        1 => *remaining.get(immediate_offset)? as i8 as i64 as u64,
        4 => read_i32(remaining, immediate_offset)? as i64 as u64,
        _ => return None,
    };
    let typed_operands = vec![
        rm_operand,
        DecodedOperand::immediate(
            OperandRole::Source,
            immediate,
            Some(spec.immediate_width_bits),
        ),
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: spec.mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: spec.confidence,
    })
}

fn decode_group1_rm32_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(opcode_offset)?;
    let spec = match opcode {
        0x81 => ImmRmInstructionSpec {
            mnemonic: "",
            modrm_reg: 0,
            immediate_width_bits: 32,
            immediate_size: 4,
            confidence: 0.58,
        },
        0x83 => ImmRmInstructionSpec {
            mnemonic: "",
            modrm_reg: 0,
            immediate_width_bits: 8,
            immediate_size: 1,
            confidence: 0.58,
        },
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let mnemonic = match modrm.reg {
        0 => "add",
        1 => "or",
        2 => "adc",
        3 => "sbb",
        4 => "and",
        5 => "sub",
        6 => "xor",
        _ => return None,
    };
    let (destination, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let immediate_end = immediate_offset + spec.immediate_size;
    let immediate = match spec.immediate_size {
        1 => *remaining.get(immediate_offset)? as i8 as i64 as u64,
        4 => read_i32(remaining, immediate_offset)? as i64 as u64,
        _ => return None,
    };
    let typed_operands = vec![
        destination,
        DecodedOperand::immediate(
            OperandRole::Source,
            immediate,
            Some(spec.immediate_width_bits),
        ),
    ];
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands: typed_operands
            .iter()
            .map(|operand| operand.text.as_str())
            .collect::<Vec<_>>()
            .join(","),
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: spec.confidence,
    })
}

fn decode_inc_dec_rm32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0xff {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let mnemonic = match modrm.reg {
        0 => "inc",
        1 => "dec",
        _ => return None,
    };
    let (operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let operands = operand.text.clone();
    let typed_operands = vec![operand];
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_inc_dec_rm8(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0xfe {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let mnemonic = match modrm.reg {
        0 => "inc",
        1 => "dec",
        _ => return None,
    };
    let (operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(8))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let operands = operand.text.clone();
    let typed_operands = vec![operand];
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_not_neg_rm8(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0xf6 {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let mnemonic = match modrm.reg {
        2 => "not",
        3 => "neg",
        _ => return None,
    };
    let (operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(8))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let operands = operand.text.clone();
    let typed_operands = vec![operand];
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_shift_rm8_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    decode_shift_rm8_count(
        address,
        remaining,
        opcode_offset,
        rex,
        ShiftCountOperand::Immediate,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShiftCountOperand {
    Immediate,
    One,
    Cl,
}

fn decode_shift_rm8_count(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
    count: ShiftCountOperand,
) -> Option<DecodedInstruction> {
    let expected_opcode = match count {
        ShiftCountOperand::Immediate => 0xc0,
        ShiftCountOperand::One => 0xd0,
        ShiftCountOperand::Cl => 0xd2,
    };
    if *remaining.get(opcode_offset)? != expected_opcode {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let mnemonic = match modrm.reg {
        4 => "shl",
        5 => "shr",
        7 => "sar",
        _ => return None,
    };
    let (destination, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(8))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let (source, size) = match count {
        ShiftCountOperand::Immediate => (
            DecodedOperand::immediate(
                OperandRole::Source,
                *remaining.get(immediate_offset)? as u64,
                Some(8),
            ),
            immediate_offset + 1,
        ),
        ShiftCountOperand::One => (
            DecodedOperand::immediate(OperandRole::Source, 1, Some(8)),
            immediate_offset,
        ),
        ShiftCountOperand::Cl => (
            DecodedOperand::register_with_width(OperandRole::Source, "cl", Some(8)),
            immediate_offset,
        ),
    };
    let typed_operands = vec![destination, source];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_shift_rm32_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    decode_shift_rm32_count(
        address,
        remaining,
        opcode_offset,
        rex,
        ShiftCountOperand::Immediate,
    )
}

fn decode_shift_rm32_count(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
    count: ShiftCountOperand,
) -> Option<DecodedInstruction> {
    let expected_opcode = match count {
        ShiftCountOperand::Immediate => 0xc1,
        ShiftCountOperand::One => 0xd1,
        ShiftCountOperand::Cl => 0xd3,
    };
    if *remaining.get(opcode_offset)? != expected_opcode {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let mnemonic = match modrm.reg {
        4 => "shl",
        5 => "shr",
        7 => "sar",
        _ => return None,
    };
    let (destination, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let (source, size) = match count {
        ShiftCountOperand::Immediate => (
            DecodedOperand::immediate(
                OperandRole::Source,
                *remaining.get(immediate_offset)? as u64,
                Some(8),
            ),
            immediate_offset + 1,
        ),
        ShiftCountOperand::One => (
            DecodedOperand::immediate(OperandRole::Source, 1, Some(8)),
            immediate_offset,
        ),
        ShiftCountOperand::Cl => (
            DecodedOperand::register_with_width(OperandRole::Source, "cl", Some(8)),
            immediate_offset,
        ),
    };
    let typed_operands = vec![destination, source];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_not_neg_rm32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0xf7 {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let mnemonic = match modrm.reg {
        2 => "not",
        3 => "neg",
        _ => return None,
    };
    let (operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let operands = operand.text.clone();
    let typed_operands = vec![operand];
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_mov_rm32_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0xc7 {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.reg != 0 {
        return None;
    }
    let (destination, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let immediate_end = immediate_offset + 4;
    let immediate = read_i32(remaining, immediate_offset)? as i64 as u64;
    let typed_operands = vec![
        destination,
        DecodedOperand::immediate(OperandRole::Source, immediate, Some(32)),
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: "mov".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.6,
    })
}

fn decode_mov_rm8_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0xc6 {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.reg != 0 {
        return None;
    }
    let (destination, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr8(modrm.rm | rex.b(), rex.present()),
                Some(8),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(8))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let immediate = *remaining.get(immediate_offset)? as u64;
    let immediate_end = immediate_offset + 1;
    let typed_operands = vec![
        destination,
        DecodedOperand::immediate(OperandRole::Source, immediate, Some(8)),
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: "mov".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_test_rm32_imm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0xf7 {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.reg != 0 {
        return None;
    }
    let (rm_operand, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Source,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Source, memory.spec),
            memory.size,
        )
    };
    let immediate = read_i32(remaining, immediate_offset)? as i64 as u64;
    let immediate_end = immediate_offset + 4;
    let typed_operands = vec![
        rm_operand,
        DecodedOperand::immediate(OperandRole::Source, immediate, Some(32)),
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: "test".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_test_rm32_r32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x85 {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    let (rm, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Source,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Source, memory.spec),
            memory.size,
        )
    };
    let reg = DecodedOperand::register_with_width(
        OperandRole::Source,
        gpr32(modrm.reg | rex.r()),
        Some(32),
    );
    let typed_operands = vec![rm, reg];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "test".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_mov_rm16_imm(address: u64, remaining: &[u8]) -> Option<DecodedInstruction> {
    if remaining.get(0..2)? != [0x66, 0xc7] {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(2)?);
    if modrm.reg != 0 {
        return None;
    }
    let (destination, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Destination,
                gpr16(modrm.rm),
                Some(16),
            ),
            3,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, RexPrefix::default(), modrm, 3, Some(16))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let immediate = read_u16(remaining, immediate_offset)? as u64;
    let immediate_end = immediate_offset + 2;
    let typed_operands = vec![
        destination,
        DecodedOperand::immediate(OperandRole::Source, immediate, Some(16)),
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: "mov".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.56,
    })
}

fn decode_mov_reg_imm32(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    register_extension: u8,
) -> DecodedInstruction {
    let opcode = remaining[opcode_offset];
    let immediate_offset = opcode_offset + 1;
    let size = opcode_offset + 5;
    let register = gpr32((opcode - 0xb8) | register_extension);
    let immediate = read_u32(remaining, immediate_offset).unwrap_or_default() as u64;
    let typed_operands = vec![
        DecodedOperand::register_with_width(OperandRole::Destination, register, Some(32)),
        DecodedOperand::immediate(OperandRole::Source, immediate, Some(32)),
    ];
    DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "mov".to_string(),
        operands: format!("{register},0x{immediate:x}"),
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.65,
    }
}

fn decode_rex_w_mov_reg_imm64(
    address: u64,
    remaining: &[u8],
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(1)?;
    let register = gpr64((opcode - 0xb8) | rex.b());
    let immediate = read_u64(remaining, 2)?;
    let typed_operands = vec![
        DecodedOperand::register(OperandRole::Destination, register),
        DecodedOperand::immediate(OperandRole::Source, immediate, Some(64)),
    ];
    Some(DecodedInstruction {
        address,
        size: 10,
        bytes: remaining[..10].to_vec(),
        mnemonic: "mov".to_string(),
        operands: format!("{register},0x{immediate:x}"),
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.65,
    })
}

fn decode_movsxd_r64_rm32(
    address: u64,
    remaining: &[u8],
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(1)? != 0x63 {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(2)?);
    let destination = gpr64(modrm.reg | rex.r());
    let (source, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register_with_width(
                OperandRole::Source,
                gpr32(modrm.rm | rex.b()),
                Some(32),
            ),
            3,
        )
    } else {
        let memory = decode_memory_operand(address, remaining, rex, modrm, 3, Some(32))?;
        (
            DecodedOperand::memory(OperandRole::Source, memory.spec),
            memory.size,
        )
    };
    let typed_operands = vec![
        DecodedOperand::register(OperandRole::Destination, destination),
        source,
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "movsxd".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.58,
    })
}

fn decode_lea_rm(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
    width_bits: u16,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x8d {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.mode == 0b11 {
        return None;
    }
    let destination = if width_bits == 64 {
        gpr64(modrm.reg | rex.r())
    } else {
        gpr32(modrm.reg | rex.r())
    };
    let mut memory =
        decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, None)?;
    memory.spec.width_bits = Some(width_bits);
    let typed_operands = vec![
        DecodedOperand::register_with_width(
            OperandRole::Destination,
            destination,
            Some(width_bits),
        ),
        DecodedOperand::memory(OperandRole::DataReference, memory.spec),
    ];
    let data_target = typed_operands
        .iter()
        .find_map(DecodedOperand::data_reference_target);
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: memory.size,
        bytes: remaining[..memory.size].to_vec(),
        mnemonic: "lea".to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target,
        confidence: 0.6,
    })
}

fn decode_rex_w_reg_rm(
    address: u64,
    remaining: &[u8],
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(1)?;
    let spec = match opcode {
        0x11 => RegRmInstructionSpec {
            mnemonic: "adc",
            direction: RegRmDirection::RegToRm,
            mutates_destination: true,
            confidence: 0.58,
        },
        0x13 => RegRmInstructionSpec {
            mnemonic: "adc",
            direction: RegRmDirection::RmToReg,
            mutates_destination: true,
            confidence: 0.58,
        },
        0x19 => RegRmInstructionSpec {
            mnemonic: "sbb",
            direction: RegRmDirection::RegToRm,
            mutates_destination: true,
            confidence: 0.58,
        },
        0x1b => RegRmInstructionSpec {
            mnemonic: "sbb",
            direction: RegRmDirection::RmToReg,
            mutates_destination: true,
            confidence: 0.58,
        },
        0x31 => RegRmInstructionSpec {
            mnemonic: "xor",
            direction: RegRmDirection::RegToRm,
            mutates_destination: true,
            confidence: 0.58,
        },
        0x33 => RegRmInstructionSpec {
            mnemonic: "xor",
            direction: RegRmDirection::RmToReg,
            mutates_destination: true,
            confidence: 0.58,
        },
        0x39 => RegRmInstructionSpec {
            mnemonic: "cmp",
            direction: RegRmDirection::RegToRm,
            mutates_destination: false,
            confidence: 0.58,
        },
        0x3b => RegRmInstructionSpec {
            mnemonic: "cmp",
            direction: RegRmDirection::RmToReg,
            mutates_destination: false,
            confidence: 0.58,
        },
        0x85 => RegRmInstructionSpec {
            mnemonic: "test",
            direction: RegRmDirection::RegToRm,
            mutates_destination: false,
            confidence: 0.58,
        },
        0x89 => RegRmInstructionSpec {
            mnemonic: "mov",
            direction: RegRmDirection::RegToRm,
            mutates_destination: true,
            confidence: 0.6,
        },
        0x8b => RegRmInstructionSpec {
            mnemonic: "mov",
            direction: RegRmDirection::RmToReg,
            mutates_destination: true,
            confidence: 0.6,
        },
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(2)?);
    if modrm.mode == 0b11 {
        return Some(register_reg_instruction(
            address, remaining, rex, modrm, spec,
        ));
    }

    let memory = decode_memory_operand(address, remaining, rex, modrm, 3, Some(64))?;
    let register = DecodedOperand::register(
        register_role(spec.direction, spec.mutates_destination),
        gpr64(modrm.reg | rex.r()),
    );
    let memory_operand = DecodedOperand::memory(
        memory_role(spec.direction, spec.mutates_destination),
        memory.spec,
    );
    let typed_operands = match spec.direction {
        RegRmDirection::RegToRm => vec![memory_operand, register],
        RegRmDirection::RmToReg => vec![register, memory_operand],
    };
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: memory.size,
        bytes: remaining[..memory.size].to_vec(),
        mnemonic: spec.mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: spec.confidence,
    })
}

fn decode_ff_group_instruction(
    address: u64,
    remaining: &[u8],
    rex: RexPrefix,
    modrm_offset: usize,
) -> Option<DecodedInstruction> {
    let modrm = ModRm::parse(*remaining.get(modrm_offset)?);
    let (mnemonic, flow, role) = match modrm.reg {
        2 => ("call", InstructionFlow::Call, OperandRole::CallTarget),
        4 => ("jmp", InstructionFlow::Jump, OperandRole::BranchTarget),
        6 => ("push", InstructionFlow::None, OperandRole::Source),
        _ => return None,
    };
    let (operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register(role, gpr64(modrm.rm | rex.b())),
            modrm_offset + 1,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, modrm_offset + 1, Some(64))?;
        (DecodedOperand::memory(role, memory.spec), memory.size)
    };
    let data_target = if flow != InstructionFlow::None {
        operand.data_reference_target()
    } else {
        None
    };
    let operands = operand.text.clone();
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        typed_operands: vec![operand],
        flow,
        target: None,
        data_target,
        confidence: 0.58,
    })
}

fn decode_pop_rm64(
    address: u64,
    remaining: &[u8],
    opcode_offset: usize,
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    if *remaining.get(opcode_offset)? != 0x8f {
        return None;
    }
    let modrm = ModRm::parse(*remaining.get(opcode_offset + 1)?);
    if modrm.reg != 0 {
        return None;
    }
    let (operand, size) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register(OperandRole::Destination, gpr64(modrm.rm | rex.b())),
            opcode_offset + 2,
        )
    } else {
        let memory =
            decode_memory_operand(address, remaining, rex, modrm, opcode_offset + 2, Some(64))?;
        (
            DecodedOperand::memory(OperandRole::Destination, memory.spec),
            memory.size,
        )
    };
    let operands = operand.text.clone();
    Some(DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: "pop".to_string(),
        operands,
        typed_operands: vec![operand],
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: 0.62,
    })
}

fn decode_rex_w_rm_imm(
    address: u64,
    remaining: &[u8],
    rex: RexPrefix,
) -> Option<DecodedInstruction> {
    let opcode = *remaining.get(1)?;
    let spec = match opcode {
        0x81 => ImmRmInstructionSpec {
            mnemonic: "cmp",
            modrm_reg: 7,
            immediate_width_bits: 32,
            immediate_size: 4,
            confidence: 0.58,
        },
        0x83 => ImmRmInstructionSpec {
            mnemonic: "cmp",
            modrm_reg: 7,
            immediate_width_bits: 8,
            immediate_size: 1,
            confidence: 0.58,
        },
        0xc7 => ImmRmInstructionSpec {
            mnemonic: "mov",
            modrm_reg: 0,
            immediate_width_bits: 32,
            immediate_size: 4,
            confidence: 0.6,
        },
        0xf7 => ImmRmInstructionSpec {
            mnemonic: "test",
            modrm_reg: 0,
            immediate_width_bits: 32,
            immediate_size: 4,
            confidence: 0.58,
        },
        _ => return None,
    };
    let modrm = ModRm::parse(*remaining.get(2)?);
    if modrm.reg != spec.modrm_reg {
        return None;
    }

    let (rm_operand, immediate_offset) = if modrm.mode == 0b11 {
        (
            DecodedOperand::register(
                if spec.mnemonic == "mov" {
                    OperandRole::Destination
                } else {
                    OperandRole::Source
                },
                gpr64(modrm.rm | rex.b()),
            ),
            3,
        )
    } else {
        let memory = decode_memory_operand(address, remaining, rex, modrm, 3, Some(64))?;
        (
            DecodedOperand::memory(
                if spec.mnemonic == "mov" {
                    OperandRole::Destination
                } else {
                    OperandRole::Source
                },
                memory.spec,
            ),
            memory.size,
        )
    };
    let immediate_end = immediate_offset + spec.immediate_size;
    let immediate = match spec.immediate_size {
        1 => *remaining.get(immediate_offset)? as i8 as i64 as u64,
        4 => read_i32(remaining, immediate_offset)? as i64 as u64,
        _ => return None,
    };
    let typed_operands = vec![
        rm_operand,
        DecodedOperand::immediate(
            OperandRole::Source,
            immediate,
            Some(spec.immediate_width_bits),
        ),
    ];
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some(DecodedInstruction {
        address,
        size: immediate_end,
        bytes: remaining[..immediate_end].to_vec(),
        mnemonic: spec.mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: spec.confidence,
    })
}

fn register_reg_instruction(
    address: u64,
    remaining: &[u8],
    rex: RexPrefix,
    modrm: ModRm,
    spec: RegRmInstructionSpec,
) -> DecodedInstruction {
    let rm = DecodedOperand::register(
        memory_role(spec.direction, spec.mutates_destination),
        gpr64(modrm.rm | rex.b()),
    );
    let reg = DecodedOperand::register(
        register_role(spec.direction, spec.mutates_destination),
        gpr64(modrm.reg | rex.r()),
    );
    let typed_operands = match spec.direction {
        RegRmDirection::RegToRm => vec![rm, reg],
        RegRmDirection::RmToReg => vec![reg, rm],
    };
    let operands = typed_operands
        .iter()
        .map(|operand| operand.text.as_str())
        .collect::<Vec<_>>()
        .join(",");
    DecodedInstruction {
        address,
        size: 3,
        bytes: remaining[..3].to_vec(),
        mnemonic: spec.mnemonic.to_string(),
        operands,
        typed_operands,
        flow: InstructionFlow::None,
        target: None,
        data_target: None,
        confidence: spec.confidence,
    }
}

fn register_role(direction: RegRmDirection, mutates_destination: bool) -> OperandRole {
    match (direction, mutates_destination) {
        (RegRmDirection::RegToRm, _) => OperandRole::Source,
        (RegRmDirection::RmToReg, true) => OperandRole::Destination,
        (RegRmDirection::RmToReg, false) => OperandRole::Source,
    }
}

fn memory_role(direction: RegRmDirection, mutates_destination: bool) -> OperandRole {
    match (direction, mutates_destination) {
        (RegRmDirection::RegToRm, true) => OperandRole::Destination,
        (RegRmDirection::RegToRm, false) => OperandRole::Source,
        (RegRmDirection::RmToReg, _) => OperandRole::Source,
    }
}

#[derive(Debug, Clone)]
struct DecodedMemoryOperand {
    spec: MemoryOperandSpec,
    size: usize,
}

fn decode_memory_operand(
    address: u64,
    remaining: &[u8],
    rex: RexPrefix,
    modrm: ModRm,
    cursor: usize,
    width_bits: Option<u16>,
) -> Option<DecodedMemoryOperand> {
    if modrm.mode == 0b11 {
        return None;
    }

    let mut size = cursor;
    let mut base = None;
    let mut index = None;
    let mut scale = None;
    let mut displacement = 0i64;
    let mut absolute_displacement = false;
    let mut rip_relative = false;

    if modrm.rm == 0b100 {
        let sib = *remaining.get(size)?;
        size += 1;
        let sib_scale = 1u8 << (sib >> 6);
        let sib_index = (sib >> 3) & 0x07;
        let sib_base = sib & 0x07;
        if sib_index != 0b100 {
            index = Some(gpr64(sib_index | rex.x()).to_string());
            scale = Some(sib_scale);
        }
        if modrm.mode == 0 && sib_base == 0b101 {
            displacement = read_i32(remaining, size)? as i64;
            size += 4;
            absolute_displacement = true;
        } else {
            base = Some(gpr64(sib_base | rex.b()).to_string());
        }
    } else if modrm.mode == 0 && modrm.rm == 0b101 {
        displacement = read_i32(remaining, size)? as i64;
        size += 4;
        rip_relative = true;
    } else {
        base = Some(gpr64(modrm.rm | rex.b()).to_string());
    }

    match modrm.mode {
        0 => {}
        1 => {
            displacement = *remaining.get(size)? as i8 as i64;
            size += 1;
        }
        2 => {
            displacement = read_i32(remaining, size)? as i64;
            size += 4;
        }
        _ => return None,
    }

    let effective_address = if rip_relative {
        Some(relative_target(address, size as u64, displacement))
    } else if absolute_displacement && index.is_none() && displacement >= 0 {
        Some(displacement as u64)
    } else {
        None
    };
    Some(DecodedMemoryOperand {
        spec: MemoryOperandSpec {
            text: memory_operand_text(
                width_bits,
                base.as_deref(),
                index.as_deref(),
                scale,
                displacement,
            ),
            base,
            index,
            scale,
            displacement: Some(displacement),
            effective_address,
            width_bits,
        },
        size,
    })
}

fn memory_operand_text(
    width_bits: Option<u16>,
    base: Option<&str>,
    index: Option<&str>,
    scale: Option<u8>,
    displacement: i64,
) -> String {
    let mut terms = Vec::new();
    if let Some(base) = base {
        terms.push(base.to_string());
    }
    if let Some(index) = index {
        if scale.unwrap_or(1) > 1 {
            terms.push(format!("{index}*{}", scale.unwrap_or(1)));
        } else {
            terms.push(index.to_string());
        }
    }
    if displacement != 0 || terms.is_empty() {
        terms.push(format_displacement(displacement));
    }
    let width = width_bits.map(width_prefix).unwrap_or("");
    format!("{width}[{}]", join_memory_terms(&terms))
}

fn join_memory_terms(terms: &[String]) -> String {
    let mut text = String::new();
    for term in terms {
        if text.is_empty() || term.starts_with('-') {
            text.push_str(term);
        } else {
            text.push('+');
            text.push_str(term);
        }
    }
    text
}

fn format_displacement(displacement: i64) -> String {
    if displacement < 0 {
        format!("-0x{:x}", displacement.unsigned_abs())
    } else {
        format!("0x{displacement:x}")
    }
}

fn width_prefix(width_bits: u16) -> &'static str {
    match width_bits {
        64 => "qword ptr ",
        32 => "dword ptr ",
        16 => "word ptr ",
        8 => "byte ptr ",
        _ => "",
    }
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    let bytes = bytes.get(offset..offset + 4)?;
    Some(i32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let bytes = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let bytes = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let bytes = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn gpr64(index: u8) -> &'static str {
    match index & 0x0f {
        0 => "rax",
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        7 => "rdi",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        _ => "r15",
    }
}

fn gpr32(index: u8) -> &'static str {
    match index & 0x0f {
        0 => "eax",
        1 => "ecx",
        2 => "edx",
        3 => "ebx",
        4 => "esp",
        5 => "ebp",
        6 => "esi",
        7 => "edi",
        8 => "r8d",
        9 => "r9d",
        10 => "r10d",
        11 => "r11d",
        12 => "r12d",
        13 => "r13d",
        14 => "r14d",
        _ => "r15d",
    }
}

fn gpr16(index: u8) -> &'static str {
    match index & 0x0f {
        0 => "ax",
        1 => "cx",
        2 => "dx",
        3 => "bx",
        4 => "sp",
        5 => "bp",
        6 => "si",
        7 => "di",
        8 => "r8w",
        9 => "r9w",
        10 => "r10w",
        11 => "r11w",
        12 => "r12w",
        13 => "r13w",
        14 => "r14w",
        _ => "r15w",
    }
}

fn gpr8(index: u8, rex_present: bool) -> &'static str {
    match index & 0x0f {
        0 => "al",
        1 => "cl",
        2 => "dl",
        3 => "bl",
        4 if rex_present => "spl",
        4 => "ah",
        5 if rex_present => "bpl",
        5 => "ch",
        6 if rex_present => "sil",
        6 => "dh",
        7 if rex_present => "dil",
        7 => "bh",
        8 => "r8b",
        9 => "r9b",
        10 => "r10b",
        11 => "r11b",
        12 => "r12b",
        13 => "r13b",
        14 => "r14b",
        _ => "r15b",
    }
}

fn rip_relative_instruction(
    address: u64,
    remaining: &[u8],
    size: usize,
    displacement: i32,
    spec: RipRelativeSpec,
) -> DecodedInstruction {
    let target = relative_target(address, size as u64, displacement as i64);
    let mut typed_operands = Vec::new();
    if let Some(register) = spec.destination_register {
        typed_operands.push(DecodedOperand::register_with_width(
            OperandRole::Destination,
            register,
            spec.destination_width_bits,
        ));
    }
    typed_operands.push(DecodedOperand::memory(
        spec.memory_role,
        MemoryOperandSpec {
            text: format!("{} -> 0x{target:016x}", spec.memory_template),
            base: Some("rip".to_string()),
            index: None,
            scale: None,
            displacement: Some(displacement as i64),
            effective_address: Some(target),
            width_bits: spec.width_bits,
        },
    ));
    let data_target = typed_operands
        .iter()
        .find_map(DecodedOperand::data_reference_target);
    DecodedInstruction {
        address,
        size,
        bytes: remaining[..size].to_vec(),
        mnemonic: spec.mnemonic.to_string(),
        operands: render_rip_relative_operands(&spec, target),
        typed_operands,
        flow: spec.flow,
        target: None,
        data_target,
        confidence: 0.62,
    }
}

fn render_rip_relative_operands(spec: &RipRelativeSpec, target: u64) -> String {
    if let Some(register) = spec.destination_register {
        format!("{register},{} -> 0x{target:016x}", spec.memory_template)
    } else {
        format!("{} -> 0x{target:016x}", spec.operand_template)
    }
}

fn raw_operands(text: &str) -> Vec<DecodedOperand> {
    if text.is_empty() {
        Vec::new()
    } else {
        vec![DecodedOperand::raw(OperandRole::Unknown, text)]
    }
}

fn control_operand_role(flow: InstructionFlow) -> OperandRole {
    match flow {
        InstructionFlow::Call => OperandRole::CallTarget,
        InstructionFlow::Jump | InstructionFlow::ConditionalBranch => OperandRole::BranchTarget,
        InstructionFlow::None | InstructionFlow::Return => OperandRole::Unknown,
    }
}

fn relative_target(address: u64, instruction_size: u64, displacement: i64) -> u64 {
    if displacement >= 0 {
        address
            .saturating_add(instruction_size)
            .saturating_add(displacement as u64)
    } else {
        address
            .saturating_add(instruction_size)
            .saturating_sub(displacement.unsigned_abs())
    }
}

fn jcc_mnemonic(opcode: u8) -> &'static str {
    match opcode & 0x0f {
        0x0 => "jo",
        0x1 => "jno",
        0x2 => "jb",
        0x3 => "jae",
        0x4 => "je",
        0x5 => "jne",
        0x6 => "jbe",
        0x7 => "ja",
        0x8 => "js",
        0x9 => "jns",
        0xa => "jp",
        0xb => "jnp",
        0xc => "jl",
        0xd => "jge",
        0xe => "jle",
        _ => "jg",
    }
}

fn cmovcc_suffix(opcode: u8) -> &'static str {
    match opcode & 0x0f {
        0x0 => "o",
        0x1 => "no",
        0x2 => "b",
        0x3 => "ae",
        0x4 => "e",
        0x5 => "ne",
        0x6 => "be",
        0x7 => "a",
        0x8 => "s",
        0x9 => "ns",
        0xa => "p",
        0xb => "np",
        0xc => "l",
        0xd => "ge",
        0xe => "le",
        _ => "g",
    }
}

pub(crate) fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
