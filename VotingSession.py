

class VotingSession:

    """
        Create a new Session for voting

        Args:
            sessionName: Identifier of this session, created by user and for further addressing
            canditeades: List of candidates of this session
            sessionMode: How the session will end, time based or maximum vote quota
            duration: If sessionMode is time based, how long session will last
            maxVotes: If sessionMode is vote count based, how many votes before ending voting session
    """
    def __init__(self, sessionName, candidates, sessionMode, duration=None, maxVotes=None, candidatesFormat="List"):

        self.id = sessionName

        # Dictionary for counting votes for each candidate
        if candidatesFormat == "Dictionary":
            self.candidates = candidates
        else:
            self.candidates = { candidate:0 for candidate in candidates }

        self.sessionMode = sessionMode
        self.duration = duration
        self.maxVotes = maxVotes

