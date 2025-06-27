package soulsoft_security_asn1

private let ClassMask = 0b1100_0000
private let ConstructedMask = 0b0010_0000
private let ControlMask = ClassMask | ConstructedMask
private let TagNumberMask = 0b0001_1111


public class AsnTag {
    private let _tagValue: Int64
    private let _controlFlags: Byte
   
    public init(controlFlags: Byte , tagValue: Int64) {
        _tagValue = tagValue
        _controlFlags = controlFlags
    }

    public prop tagValue: Int64 {
        get() {
            _tagValue
        }
    }

    public prop isConstructed: Bool {
        get() {
            (Int64(_controlFlags) & ConstructedMask) != 0
        }
    }
}