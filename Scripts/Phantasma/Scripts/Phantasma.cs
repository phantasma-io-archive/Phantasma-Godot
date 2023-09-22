namespace Phantasma 
{
	
    public enum EventKind
    {
        Unknown = 0,
        ChainCreate = 1,
        TokenCreate = 2,
        TokenSend = 3,
        TokenReceive = 4,
        TokenMint = 5,
        TokenBurn = 6,
        TokenStake = 7,
        TokenClaim = 8,
        AddressRegister = 9,
        AddressLink = 10,
        AddressUnlink = 11,
        OrganizationCreate = 12,
        OrganizationAdd = 13,
        OrganizationRemove = 14,
        GasEscrow = 15,
        GasPayment = 16,
        AddressUnregister = 17,
        OrderCreated = 18,
        OrderCancelled = 19,
        OrderFilled = 20,
        OrderClosed = 21,
        FeedCreate = 22,
        FeedUpdate = 23,
        FileCreate = 24,
        FileDelete = 25,
        ValidatorPropose = 26,
        ValidatorElect = 27,
        ValidatorRemove = 28,
        ValidatorSwitch = 29,
        PackedNFT = 30,
        ValueCreate = 31,
        ValueUpdate = 32,
        PollCreated = 33,
        PollClosed = 34,
        PollVote = 35,
        ChannelCreate = 36,
        ChannelRefill = 37,
        ChannelSettle = 38,
        LeaderboardCreate = 39,
        LeaderboardInsert = 40,
        LeaderboardReset = 41,
        PlatformCreate = 42,
        ChainSwap = 43,
        ContractRegister = 44,
        ContractDeploy = 45,
        AddressMigration = 46,
        ContractUpgrade = 47,
        Log = 48,
        Inflation = 49,
        OwnerAdded = 50,
        OwnerRemoved = 51,
        DomainCreate = 52,
        DomainDelete = 53,
        TaskStart = 54,
        TaskStop = 55,
        CrownRewards = 56,
        Infusion = 57,
        Crowdsale = 58,
        OrderBid = 59,
        ContractKill = 60,
        OrganizationKill = 61,
        MasterClaim = 62,
        ExecutionFailure = 63,
        Custom = 64
    }

    public struct Address: ISerializable, IComparable<Address>
    {
        public static readonly Address Null = new Address(NullPublicKey);

        public static readonly string NullText = "NULL";
        private static byte[] NullPublicKey => new byte[LengthInBytes];

        private byte[] _bytes;

        public const int LengthInBytes = 34;
        public const int MaxPlatformNameLength = 10;

        public AddressKind Kind => IsNull ? AddressKind.System : (_bytes[0] >= 3) ? AddressKind.Interop 
            : (AddressKind)_bytes[0];

        public bool IsSystem => Kind == AddressKind.System;

        public bool IsInterop => Kind == AddressKind.Interop;

        public bool IsUser => Kind == AddressKind.User;

        public string TendermintAddress => Base16.Encode(_bytes[2..].Sha256()[..20]);

        public byte[] TendermintPublicKey => _bytes[2..].Sha256()[..20];

        public bool IsNull
        {
            get
            {
                if (_bytes == null || _bytes.Length == 0)
                {
                    return true;
                }

                for (int i = 1; i < _bytes.Length; i++)
                {
                    if (_bytes[i] != 0)
                    {
                        return false;
                    }
                }

                return true;
            }
        }

        private string _text;

        private static Dictionary<byte[], string> _keyToTextCache = new Dictionary<byte[], string>(new ByteArrayComparer());

        public string Text
        {
            get
            {
                if (IsNull)
                {
                    return NullText;
                }

                if (string.IsNullOrEmpty(_text))
                {
                    lock (_keyToTextCache) {
                        if (_keyToTextCache.ContainsKey(_bytes))
                        {
                            _text = _keyToTextCache[_bytes];
                        }
                    }

                    if (string.IsNullOrEmpty(_text))
                    {
                        char prefix;

                        switch (Kind)
                        {
                            case AddressKind.User: prefix = 'P'; break;
                            case AddressKind.Interop: prefix = 'X'; break;
                            default: prefix = 'S'; break;

                        }
                        _text = prefix + Base58.Encode(_bytes);
                        lock (_keyToTextCache) {
                            _keyToTextCache[_bytes] = _text;
                        }
                    }
                }

                return _text;
            }
        }

        private Address(byte[] publicKey)
        {
            Throw.IfNull(publicKey, "publicKey");
            if (publicKey.Length != LengthInBytes)
            {
                throw new Exception($"publicKey length must be {LengthInBytes}");
            }
            _bytes = new byte[LengthInBytes];
            Array.Copy(publicKey, this._bytes, LengthInBytes);
            this._text = null;
        }

        public static Address FromBytes(byte[] bytes)
        {
            return new Address(bytes);
        }

        public static Address FromKey(IKeyPair key)
        {
            var bytes = new byte[LengthInBytes];
            bytes[0] = (byte)AddressKind.User;

            if (key.PublicKey.Length == 32)
            {
                ByteArrayUtils.CopyBytes(key.PublicKey, 0, bytes, 2, 32);
            }
            else if (key.PublicKey.Length == 33)
            {
                ByteArrayUtils.CopyBytes(key.PublicKey, 0, bytes, 1, 33);
            }
            else
            {
                throw new Exception("Invalid public key length");
            }

            return new Address(bytes);
        }

        public static Address FromHash(string str)
        {
            var bytes = Encoding.UTF8.GetBytes(str);
            return FromHash(bytes);
        }

        public static Address FromHash(byte[] input)
        {
            var hash = CryptoExtensions.Sha256(input);
            var bytes = ByteArrayUtils.ConcatBytes(new byte[] { (byte)AddressKind.System, 0 }, hash);
            return new Address(bytes);
        }

        public static bool operator ==(Address A, Address B)
        {
            if (A._bytes == null)
            {
                return B._bytes == null;
            }

            if (B._bytes == null || A._bytes.Length != B._bytes.Length)
            {
                return false;
            }

            for (int i = 0; i < A._bytes.Length; i++)
            {
                if (A._bytes[i] != B._bytes[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static bool operator !=(Address A, Address B)
        {
            if (A._bytes == null)
            {
                return B._bytes != null;
            }

            if (B._bytes == null || A._bytes.Length != B._bytes.Length)
            {
                return true;
            }

            for (int i = 0; i < A._bytes.Length; i++)
            {
                if (A._bytes[i] != B._bytes[i])
                {
                    return true;
                }
            }
            return false;
        }

        public override string ToString()
        {
            if (this.IsNull)
            {
                return "[Null address]";
            }

            return this.Text;
        }

        public override bool Equals(object obj)
        {
            if (!(obj is Address))
            {
                return false;
            }

            var otherAddress = (Address)obj;

            var thisBytes = this._bytes;
            var otherBytes = otherAddress._bytes;

            if ((thisBytes == null) || (otherBytes == null))
            {
                if (thisBytes == null && otherBytes != null && otherAddress.IsNull)
                {
                    return true;
                }

                if (otherBytes == null && thisBytes != null && this.IsNull)
                {
                    return true;
                }

                return (thisBytes == null) == (otherBytes == null);
            }

            if (thisBytes.Length != otherBytes.Length) // failsafe, should never happen
            {
                return false;
            }

            for (int i=0; i<thisBytes.Length; i++)
            {
                if (thisBytes[i] != otherBytes[i])
                {
                    return false;
                }
            }

            return true;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (int)Murmur32.Hash(_bytes);
            }
        }

        public static Address FromWIF(string WIF)
        {
            var keyPair = PhantasmaKeys.FromWIF(WIF);
            return keyPair.Address;
        }

        private static Dictionary<string, Address> _textToAddressCache = new Dictionary<string, Address>();

        public static Address FromText(string text)
        {
            return Address.Parse(text);
        }

        public static Address Parse(string text)
        {
            Address addr;

            if (text.Equals(NullText, StringComparison.OrdinalIgnoreCase))
            {
                return Address.Null;
            }

            lock (_textToAddressCache)
            {
                if (_textToAddressCache.ContainsKey(text))
                {
                    return _textToAddressCache[text];
                }

                var originalText = text;

                var prefix = text[0];

                text = text.Substring(1);
                var bytes = Base58.Decode(text);

                Throw.If(bytes.Length != LengthInBytes, "Invalid address data");

                addr = new Address(bytes);

                switch (prefix)
                {
                    case 'P':
                        Throw.If(addr.Kind != AddressKind.User, "address should be user");
                        break;

                    case 'S':
                        Throw.If(addr.Kind != AddressKind.System, "address should be system");
                        break;

                    case 'X':
                        Throw.If(addr.Kind < AddressKind.Interop, "address should be interop");
                        break;

                    default:
                        throw new Exception("invalid address prefix: " + prefix);
                }

                _textToAddressCache[originalText] = addr;
            }

            return addr;
        }

        public int GetSize()
        {
            return LengthInBytes;
        }


        // WARNING the performance of this is not the best.
        // Rewrite it later without using try..catch and preferably also without instantiating a new address
        public static bool IsValidAddress(string text)
        {
            lock (_textToAddressCache)
            {
                if (_textToAddressCache.ContainsKey(text))
                {
                    return true;
                }
            }

            try
            {
                var addr = Address.FromText(text);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void SerializeData(BinaryWriter writer)
        {
            writer.WriteByteArray(this._bytes);
        }

        public void UnserializeData(BinaryReader reader)
        {
            this._bytes = reader.ReadByteArray();
            this._text = null;
        }

        public void DecodeInterop(out byte platformID, out byte[] publicKey)
        {
            platformID = this.PlatformID;
            publicKey = new byte[33];
            ByteArrayUtils.CopyBytes(_bytes, 1, publicKey, 0, publicKey.Length);
        }

        public byte PlatformID => (byte)(1 + _bytes[0] - AddressKind.Interop);

        public static Address EncodeAddress(byte platformID, string addressText)
        {
            Throw.If(!IsValidAddress(addressText), "invalid ethereum address");
            var input = addressText.Substring(2);
            var bytes = Base16.Decode(input);

            var pubKey = new byte[33];
            ByteArrayUtils.CopyBytes(bytes, 0, pubKey, 0, bytes.Length);
            return Address.FromInterop(platformID, pubKey);
        }
        
        public static Address FromInterop(byte platformID, byte[] publicKey)
        {
            Throw.If(publicKey == null || publicKey.Length != 33, "public key is invalid");
            Throw.If(platformID < 1, "invalid platform id");

            var bytes = new byte[LengthInBytes];
            bytes[0] = (byte)(AddressKind.Interop+platformID-1);
            ByteArrayUtils.CopyBytes(publicKey, 0, bytes, 1, publicKey.Length);
            return new Address(bytes);
        }

        public byte[] ToByteArray()
        {
            var bytes = new byte[LengthInBytes];
            if (_bytes != null)
            {
                if (_bytes.Length != LengthInBytes)
                {
                    throw new Exception("invalid address byte length");
                }
                ByteArrayUtils.CopyBytes(_bytes, 0, bytes, 0, _bytes.Length);
            }

            return bytes;
        }

        public int CompareTo(Address other)
        {
            byte[] x = ToByteArray();
            byte[] y = other.ToByteArray();
            for (int i = x.Length - 1; i >= 0; i--)
            {
                if (x[i] > y[i])
                    return 1;
                if (x[i] < y[i])
                    return -1;
            }
            return 0;
        }
        
        public string ConvertPhantasmaToEthereum()
        {
            var bytes = this.ToByteArray().Skip(1).ToArray();
            var encoded = Base16.Encode(bytes);
            return "0x" + encoded;
        }

        public bool ValidateSignedData(string signedData, string random, string data)
        {
            var msgData = Base16.Decode(data);
            var randomBytes = Base16.Decode(random);
            var signedDataBytes = Base16.Decode(signedData);
            var msgBytes = ByteArrayUtils.ConcatBytes(randomBytes, msgData);
            using (var stream = new MemoryStream(signedDataBytes))
            using (var reader = new BinaryReader(stream))
            {
                var signature = reader.ReadSignature();
                return signature.Verify(msgBytes, this);
            }
        }
    }

	public interface IKeyPair
	{
		byte[] PrivateKey { get; }
		byte[] PublicKey { get; }

		// byte[] customSignFunction(byte[] message, byte[] prikey, byte[] pubkey)
		// allows singning with custom crypto libs.
		Signature Sign(byte[] msg, Func<byte[], byte[], byte[], byte[]> customSignFunction = null);
	}

    public sealed class PhantasmaKeys : IKeyPair
    {
        public byte[] PrivateKey { get; private set; }
        public byte[] PublicKey { get; private set; }

        public readonly Address Address;
        
        public const int PrivateKeyLength = 32;

        public PhantasmaKeys(byte[] privateKey)
        {
            if (privateKey.Length == 64)
            {
                privateKey = privateKey.Take(32).ToArray();
            }

            Throw.If(privateKey.Length != PrivateKeyLength, $"privateKey should have length {PrivateKeyLength} but has {privateKey.Length}");

            this.PrivateKey = new byte[PrivateKeyLength];
            ByteArrayUtils.CopyBytes(privateKey, 0, PrivateKey, 0, PrivateKeyLength); 

            this.PublicKey = Ed25519.PublicKeyFromSeed(privateKey);
            this.Address = Address.FromKey(this);
        }

        public override string ToString()
        {
            return Address.Text;
        }

        public static PhantasmaKeys Generate()
        {
            var privateKey = Entropy.GetRandomBytes(PrivateKeyLength);
            var pair = new PhantasmaKeys(privateKey);
            return pair;
        }

        public static PhantasmaKeys FromWIF(string wif)
        {
            Throw.If(wif == null, "WIF required");

            byte[] data = wif.Base58CheckDecode();
            Throw.If(data.Length != 34 || data[0] != 0x80 || data[33] != 0x01, "Invalid WIF format");

            byte[] privateKey = new byte[32];
            ByteArrayUtils.CopyBytes(data, 1, privateKey, 0, privateKey.Length); 
            Array.Clear(data, 0, data.Length);
            return new PhantasmaKeys(privateKey);
        }

        public string ToWIF()
        {
            byte[] data = new byte[34];
            data[0] = 0x80;
            ByteArrayUtils.CopyBytes(PrivateKey, 0, data, 1, 32); 
            data[33] = 0x01;
            string wif = data.Base58CheckEncode();
            Array.Clear(data, 0, data.Length);
            return wif;
        }

        private static byte[] XOR(byte[] x, byte[] y)
        {
            if (x.Length != y.Length) throw new ArgumentException();
            return x.Zip(y, (a, b) => (byte)(a ^ b)).ToArray();
        }

        public Signature Sign(byte[] msg, Func<byte[], byte[], byte[], byte[]> customSignFunction = null)
        {
            return Ed25519Signature.Generate(this, msg);
        }
    }

    public static class Base16
    {
        private const string hexAlphabet = "0123456789ABCDEF";

        public static byte[] Decode(this string input, bool allowExceptions = true)
        {
            if (input == null || input.Length == 0)
            {
                return new byte[0];
            }

            if (input.StartsWith("0x"))
            {
                return input.Substring(2).Decode(allowExceptions);
            }

            byte[] result = null;

            if (input.Length % 2 == 0)
            {
                result = new byte[input.Length / 2];
                for (int i = 0; i < result.Length; i++)
                {
                    var str = input.Substring(i * 2, 2).ToUpper();
                    int A = hexAlphabet.IndexOf(str[0]);
                    int B = hexAlphabet.IndexOf(str[1]);

                    if (A < 0 || B < 0)
                    {
                        result = null;
                        break;
                    }

                    result[i] = (byte)(A * 16 + B);
                }
            }

            if (result != null)            
            {
                return result;
            }

            if (allowExceptions)
            {
                throw new System.Exception("base16.Decode: invalid input");
            }

            return null;
        }

        // constant time hex conversion
        // see http://stackoverflow.com/a/14333437/445517
        //
        // An explanation of the weird bit fiddling:
        //
        // 1. `bytes[i] >> 4` extracts the high nibble of a byte  
        //   `bytes[i] & 0xF` extracts the low nibble of a byte
        // 2. `b - 10`  
        //    is `< 0` for values `b < 10`, which will become a decimal digit  
        //    is `>= 0` for values `b > 10`, which will become a letter from `A` to `F`.
        // 3. Using `i >> 31` on a signed 32 bit integer extracts the sign, thanks to sign extension.
        //    It will be `-1` for `i < 0` and `0` for `i >= 0`.
        // 4. Combining 2) and 3), shows that `(b-10)>>31` will be `0` for letters and `-1` for digits.
        // 5. Looking at the case for letters, the last summand becomes `0`, and `b` is in the range 10 to 15. We want to map it to `A`(65) to `F`(70), which implies adding 55 (`'A'-10`).
        // 6. Looking at the case for digits, we want to adapt the last summand so it maps `b` from the range 0 to 9 to the range `0`(48) to `9`(57). This means it needs to become -7 (`'0' - 55`).  
        // Now we could just multiply with 7. But since -1 is represented by all bits being 1, we can instead use `& -7` since `(0 & -7) == 0` and `(-1 & -7) == -7`.
        //
        // Some further considerations:
        //
        // * I didn't use a second loop variable to index into `c`, since measurement shows that calculating it from `i` is cheaper. 
        // * Using exactly `i < bytes.Length` as upper bound of the loop allows the JITter to eliminate bounds checks on `bytes[i]`, so I chose that variant.
        // * Making `b` an int avoids unnecessary conversions from and to byte.
        public static string Encode(this byte[] input)
        {
            if (input == null) return "";
            char[] c = new char[input.Length * 2];
            int b;

            for (int i = 0; i < input.Length; i++)
            {
                b = input[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
                b = input[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
            }

            return new string(c);
        }
    }

    public delegate void CustomWriter(BinaryWriter writer, object obj);
    public delegate object CustomReader(BinaryReader reader);

    public static class Serialization
    {
        private static Dictionary<Type, CustomSerializer> _customSerializers = new Dictionary<Type, CustomSerializer>();

        public static void RegisterType<T>(CustomReader reader, CustomWriter writer)
        {
            var type = typeof(T);
            _customSerializers[type] = new CustomSerializer(reader, writer);
        }

        public static byte[] Serialize(this object obj)
        {
            if (obj == null)
            {
                return new byte[0];
            }

            if (obj.GetType() == typeof(byte[]))
            {
                return (byte[])obj;
            }

            using (var stream = new MemoryStream())
            {
                using (var writer = new BinaryWriter(stream))
                {
                    Serialize(writer, obj);
                }

                return stream.ToArray();
            }

        }

        public static void Serialize(BinaryWriter writer, object obj)
        {
            var type = obj.GetType();
            Serialize(writer, obj, type);
        }

        public static void Serialize(BinaryWriter writer, object obj, Type type)
        {
            if (_customSerializers.ContainsKey(type))
            {
                var serializer = _customSerializers[type];
                serializer.Write(writer, obj);
                return;
            }

            if (type == typeof(void))
            {
                return;
            }

            if (type == typeof(bool))
            {
                writer.Write((byte)(((bool)obj) ? 1 : 0));
            }
            else if (type == typeof(byte))
            {
                writer.Write((byte)obj);
            }
            else if (type == typeof(short))
            {
                writer.Write((short)obj);
            }
            else if (type == typeof(long))
            {
                writer.Write((long)obj);
            }
            else if (type == typeof(int))
            {
                writer.Write((int)obj);
            }
            else if (type == typeof(ushort))
            {
                writer.Write((ushort)obj);
            }
            else if (type == typeof(sbyte))
            {
                writer.Write((sbyte)obj);
            }
            else if (type == typeof(ulong))
            {
                writer.Write((ulong)obj);
            }
            else if (type == typeof(uint))
            {
                writer.Write((uint)obj);
            }
            else if (type == typeof(string))
            {
                writer.WriteVarString((string)obj);
            }
            else if (type == typeof(decimal))
            {
                writer.Write((decimal)obj);
            }
            else if (type == typeof(BigInteger))
            {
                writer.WriteBigInteger((BigInteger)obj);
            }
            else if (type == typeof(Timestamp))
            {
                writer.Write(((Timestamp)obj).Value);
            }
            else if (typeof(ISerializable).IsAssignableFrom(type))
            {
                var serializable = (ISerializable)obj;
                serializable.SerializeData(writer);
            }
            else if (type.IsArray)
            {
                var array = (Array)obj;
                if (array == null)
                {
                    writer.WriteVarInt(0);
                }
                else
                {
                    writer.WriteVarInt(array.Length);

                    var elementType = type.GetElementType();
                    for (int i = 0; i < array.Length; i++)
                    {
                        var item = array.GetValue(i);
                        Serialize(writer, item, elementType);
                    }
                }
            }
            else if (type.IsEnum)
            {
                uint val = (uint)Convert.ChangeType(obj, typeof(uint));
                writer.WriteVarInt(val);
            }
            else if (type.IsStructOrClass()) // check if struct or class
            {
                var fields = type.GetFields(BindingFlags.Public | BindingFlags.Instance);

                foreach (var field in fields)
                {
                    var val = field.GetValue(obj);
                    Serialize(writer, val, field.FieldType);
                }

                var props = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);

                foreach (var prop in props)
                {
                    var val = prop.GetValue(obj);
                    Serialize(writer, val, prop.PropertyType);
                }
            }
            else
            {
                throw new Exception("Unknown type");
            }
        }

        public static T Unserialize<T>(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return default(T);
            }

            return (T)Unserialize(bytes, typeof(T));
        }

        public static object Unserialize(byte[] bytes, Type type)
        {
            if (type == typeof(byte[]))
            {
                return bytes;
            }

            if (bytes == null || bytes.Length == 0)
            {
                return null;
            }

            using (var stream = new MemoryStream(bytes))
            {
                using (var reader = new BinaryReader(stream))
                {
                    return Unserialize(reader, type);
                }
            }
        }

        public static T Unserialize<T>(BinaryReader reader)
        {
            return (T)Unserialize(reader, typeof(T));
        }

        public static object Unserialize(BinaryReader reader, Type type)
        {
            if (_customSerializers.ContainsKey(type))
            {
                var serializer = _customSerializers[type];
                return serializer.Read(reader);
            }

            if (type == typeof(bool))
            {
                return reader.ReadByte() != 0;
            }

            if (type == typeof(byte))
            {
                return reader.ReadByte();
            }

            if (type == typeof(long))
            {
                return reader.ReadInt64();
            }

            if (type == typeof(int))
            {
                return reader.ReadInt32();
            }

            if (type == typeof(short))
            {
                return reader.ReadInt16();
            }

            if (type == typeof(sbyte))
            {
                return reader.ReadSByte();
            }

            if (type == typeof(ulong))
            {
                return reader.ReadUInt64();
            }

            if (type == typeof(uint))
            {
                return reader.ReadUInt32();
            }

            if (type == typeof(ushort))
            {
                return reader.ReadUInt16();
            }

            if (type == typeof(string))
            {
                return reader.ReadVarString();
            }

            if (type == typeof(decimal))
            {
                return reader.ReadDecimal();
            }

            if (type == typeof(BigInteger))
            {
                return reader.ReadBigInteger();
            }

            if (type == typeof(Timestamp))
            {
                return new Timestamp(reader.ReadUInt32());
            }

            if (typeof(ISerializable).IsAssignableFrom(type))
            {
                var obj = Activator.CreateInstance(type);
                var serializable = (ISerializable)obj;
                serializable.UnserializeData(reader);
                return obj;
            }

            if (type.IsArray)
            {
                var length = (int)reader.ReadVarInt();
                var arrayType = type.GetElementType();
                var array = Array.CreateInstance(arrayType, length);
                for (int i = 0; i < length; i++)
                {
                    var item = Unserialize(reader, arrayType);
                    array.SetValue(item, i);
                }

                return array;
            }

            if (type.IsEnum)
            {
                var val = (uint)reader.ReadVarInt();
                return Enum.Parse(type, val.ToString());
            }

            if (type.IsStructOrClass()) // check if struct or class
            {
                var obj = Activator.CreateInstance(type);
                var fields = type.GetFields(BindingFlags.Public | BindingFlags.Instance).OrderBy(x => x.MetadataToken);

                foreach (var field in fields)
                {
                    var fieldType = field.FieldType;

                    object val = Unserialize(reader, fieldType);
                    field.SetValue(obj, val);
                }

                var props = type.GetProperties(BindingFlags.Public | BindingFlags.Instance).OrderBy(x => x.MetadataToken);

                foreach (var prop in props)
                {
                    var propType = prop.PropertyType;

                    if (prop.CanWrite)
                    {
                        object val = Unserialize(reader, propType);
                        prop.SetValue(obj, val);
                    }
                }

                return obj;
            }

            throw new Exception("Unknown type");
        }

        public static ISerializable AsSerializable(this byte[] value, Type type)
        {
            if (!typeof(ISerializable).GetTypeInfo().IsAssignableFrom(type))
                throw new InvalidCastException();
            ISerializable serializable = (ISerializable)Activator.CreateInstance(type);
            using MemoryStream ms = new MemoryStream(value, false);
            using BinaryReader reader = new BinaryReader(ms, Encoding.UTF8, true);
            serializable.UnserializeData(reader);
            return serializable;
        }

        //// only works in structs and classes
        //public static void Copy(this object target, object source)
        //{
        //    var type = target.GetType();

        //    Throw.IfNot(type.IsStructOrClass(), "invalid type");

        //    var fields = type.GetFields();

        //    foreach (var field in fields)
        //    {
        //        var fieldType = field.FieldType;

        //        object val;
        //        if (fieldType.IsStructOrClass())
        //        {
        //            val = Activator.CreateInstance(fieldType);
        //            val.Copy(field.GetValue(source));
        //        }
        //        else
        //        {
        //            val = field.GetValue(source);
        //        }
        //        field.SetValue(target, val);
        //    }
        //}
    }

    public struct Hash : ISerializable, IComparable<Hash>, IEquatable<Hash>
    {
        public const int Length = 32;

        public static readonly Hash Null = FromBytes(new byte[Length]);

        private byte[] _data;
    
        public int Size => _data.Length;

        public bool IsNull
        {
            get
            {
                if (_data == null)
                {
                    return true;
                }

                for (int i=0; i<_data.Length; i++)
                {
                    if (_data[i] != 0)
                    {
                        return false;
                    }
                }
                return true;
            }
        }

        public override bool Equals(object obj)
        {
            if (!(obj is Hash))
                return false;

            var otherHash = (Hash)obj;

            var thisData = this._data;
            var otherData = otherHash._data;

            if (thisData.Length != otherData.Length)
            {
                return false;
            }

            for (int i = 0; i < thisData.Length; i++)
            {
                if (otherData[i] != thisData[i])
                {
                    return false;
                }
            }

            return true;
        }

        public override int GetHashCode() => (int)_data.ToUInt32(0);

        public byte[] ToByteArray()
        {
            var result = new byte[_data.Length];
            ByteArrayUtils.CopyBytes(_data, 0, result, 0, _data.Length);
            return result;
        }

        public override string ToString()
        {
            return Base16.Encode(ByteArrayUtils.ReverseBytes(_data));
        }

        public static readonly Hash Zero = new Hash();

        public Hash(byte[] value)
        {
            Throw.If(value == null, "value cannot be null");
            Throw.If(value.Length != Length, $"value must have length {Length}/{value.Length}");

            this._data = value;
        }

        public int CompareTo(Hash other)
        {
            byte[] x = ToByteArray();
            byte[] y = other.ToByteArray();
            for (int i = x.Length - 1; i >= 0; i--)
            {
                if (x[i] > y[i])
                    return 1;
                if (x[i] < y[i])
                    return -1;
            }
            return 0;
        }

        bool IEquatable<Hash>.Equals(Hash other)
        {
            return Equals(other);
        }

        public static Hash Parse(string s)
        {
            Throw.If(string.IsNullOrEmpty(s), "string cannot be empty");
            Throw.If(s.Length < 64, "string too short");

            var ch = char.ToUpper(s[1]);
            if (ch == 'X')
            {
                Throw.If(s[0] != '0', "invalid hexdecimal prefix");
                return Parse(s.Substring(2));
            }

            var ExpectedLength = Length * 2;
            Throw.If(s.Length != ExpectedLength, $"length of string must be {Length}");

            return new Hash(ByteArrayUtils.ReverseBytes(s.Decode()));
        }

        public static bool TryParse(string s, out Hash result)
        {
            if (string.IsNullOrEmpty(s))
            {
                result = Hash.Null;
                return false;
            }

            if (s.StartsWith("0x"))
            {
                return TryParse(s.Substring(2), out result);
            }
            if (s.Length != 64)
            {
                result = Hash.Null;
                return false;
            }

            try
            {
                byte[] data = Base16.Decode(s);

                result = new Hash(ByteArrayUtils.ReverseBytes(data));
                return true;
            }
            catch
            {
                result = Hash.Null;
                return false;
            }
        }

        public static bool operator ==(Hash left, Hash right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(Hash left, Hash right)
        {
            return !(left == right);
        }


        public static bool operator >(Hash left, Hash right)
        {
            return left.CompareTo(right) > 0;
        }

        public static bool operator >=(Hash left, Hash right)
        {
            return left.CompareTo(right) >= 0;
        }

        public static bool operator <(Hash left, Hash right)
        {
            return left.CompareTo(right) < 0;
        }

        public static bool operator <=(Hash left, Hash right)
        {
            return left.CompareTo(right) <= 0;
        }

        // If necessary pads the number to 32 bytes with zeros 
        public static implicit operator Hash(BigInteger val)
        {
            var src = val.ToUnsignedByteArray();
            Throw.If(src.Length > Length, "number is too large");

            return FromBytes(src);
        }

        public static Hash FromBytes(byte[] input)
        {
            if (input.Length != Length) // NOTE this is actually problematic, better to separate into 2 methods
            {
                input = CryptoExtensions.Sha256(input);
            }

            var bytes = new byte[Length];
            Array.Copy(input, bytes, input.Length);
            return new Hash(bytes);
        }

        public void SerializeData(BinaryWriter writer)
        {
            writer.WriteByteArray(this._data);
        }

        public void UnserializeData(BinaryReader reader)
        {
            this._data = reader.ReadByteArray();
        }

        public static implicit operator BigInteger(Hash val)
        {
            var result = new byte[Hash.Length];
            ByteArrayUtils.CopyBytes(val.ToByteArray(), 0, result, 0, Hash.Length);
            return new BigInteger(val.ToByteArray(), true);
        }

        public static Hash MerkleCombine(Hash A, Hash B)
        {
            var bytes = new byte[Hash.Length * 2];
            ByteArrayUtils.CopyBytes(A._data, 0, bytes, 0, Hash.Length);
            ByteArrayUtils.CopyBytes(B._data, 0, bytes, Hash.Length, Hash.Length);
            return Hash.FromBytes(bytes);
        }

        public static Hash FromString(string str)
        {
            var bytes = CryptoExtensions.Sha256(str);
            return new Hash(bytes);
        }

        public static Hash FromUnpaddedHex(string hash)
        {
            if (hash.StartsWith("0x"))
            {
                hash = hash.Substring(2);
            }

            var sb = new StringBuilder();
            sb.Append(hash);
            while (sb.Length < 64)
            {
                sb.Append('0');
                sb.Append('0');
            }

            var temp = sb.ToString();
            return Hash.Parse(temp);
        }
    }
	
}