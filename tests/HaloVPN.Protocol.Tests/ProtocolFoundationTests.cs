using HaloVPN.Protocol.Abstractions;
using HaloVPN.Shared;

namespace HaloVPN.Protocol.Tests;

public sealed class ProtocolFoundationTests
{
    [Fact]
    public void WireConstantsMatchDraft()
    {
        Assert.Equal(0, HaloProtocolConstants.WireVersion);
        Assert.Equal(24, HaloProtocolConstants.CommonHeaderSize);
        Assert.Equal(16, HaloProtocolConstants.AuthenticationTagSize);
        Assert.Equal(1400, HaloProtocolConstants.MaximumAuthenticatedDatagramSize);
    }

    [Fact]
    public void SuccessfulOperationCarriesWrittenByteCount()
    {
        var result = ProtocolOperationResult.Ok(42);

        Assert.True(result.Success);
        Assert.Equal(ProtocolErrorCode.None, result.ErrorCode);
        Assert.Equal(42, result.BytesWritten);
    }

    [Fact]
    public void FailedOperationWritesNothing()
    {
        var result = ProtocolOperationResult.Fail(ProtocolErrorCode.InvalidPacket);

        Assert.False(result.Success);
        Assert.Equal(ProtocolErrorCode.InvalidPacket, result.ErrorCode);
        Assert.Equal(0, result.BytesWritten);
    }
}
