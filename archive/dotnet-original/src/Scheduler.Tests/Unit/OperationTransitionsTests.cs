using Scheduler.Application.Persistence;

namespace Scheduler.Tests.Unit;

public sealed class OperationTransitionsTests
{
    [Theory]
    [InlineData(OperationState.Pending, OperationState.Running)]
    [InlineData(OperationState.Pending, OperationState.Failed)]
    [InlineData(OperationState.Pending, OperationState.RolledBack)]
    [InlineData(OperationState.Running, OperationState.Succeeded)]
    [InlineData(OperationState.Running, OperationState.Failed)]
    [InlineData(OperationState.Running, OperationState.RolledBack)]
    public void PermittedTransitionsAreAllowed(OperationState from, OperationState to)
    {
        Assert.True(OperationTransitions.CanTransition(from, to));
    }

    [Theory]
    [InlineData(OperationState.Pending, OperationState.Succeeded)]
    [InlineData(OperationState.Succeeded, OperationState.Running)]
    [InlineData(OperationState.Failed, OperationState.Running)]
    [InlineData(OperationState.RolledBack, OperationState.Succeeded)]
    [InlineData(OperationState.Succeeded, OperationState.Failed)]
    public void ForbiddenTransitionsAreRejected(OperationState from, OperationState to)
    {
        Assert.False(OperationTransitions.CanTransition(from, to));
        Assert.Throws<InvalidOperationException>(() => OperationTransitions.EnsureCanTransition(from, to));
    }

    [Theory]
    [InlineData(OperationState.Succeeded)]
    [InlineData(OperationState.Failed)]
    [InlineData(OperationState.RolledBack)]
    public void TerminalStatesAreTerminal(OperationState state)
    {
        Assert.True(OperationTransitions.IsTerminal(state));
    }

    [Theory]
    [InlineData(OperationState.Pending)]
    [InlineData(OperationState.Running)]
    public void ActiveStatesAreNotTerminal(OperationState state)
    {
        Assert.False(OperationTransitions.IsTerminal(state));
    }
}
