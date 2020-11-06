from functools import reduce
from datetime import datetime, timedelta

CONST_MAX_VOTES_MODE = "maxvotes"
CONST_DURATION_MODE = "duration"

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
        self.createdAt = datetime.now().isoformat()
        self.duration = duration
        self.maxVotes = maxVotes
        self.usersThatVoted = []

    """
        Validate vote and compute it

        Args:
            userID: string of the User Identifier
            candidate: string of the Candidate that will 

        Returns:
            A boolean to indicate if vote was successfully computed 
        
    """
    def vote(self, userID, candidate):

        # Validating vote
        if candidate not in self.candidates:
            return False

        if userID in self.usersThatVoted:
            return False
        
        if self.hasFinished():
            return False

        # Adding voting
        self.candidates[candidate] += 1
        self.usersThatVoted.append(userID)

        return True


    """
        Verify if session has come to an end.

        Returns:
            A boolean that shows if session is still running
    """
    def hasFinished(self):
        
        if self.sessionMode.lower() == CONST_MAX_VOTES_MODE:
            return self.countTotalVotes() >= self.maxVotes
        
        elif self.sessionMode.lower() == CONST_DURATION_MODE:
            return datetime.now() >= (datetime.fromisoformat(self.createdAt) + timedelta(minutes=self.duration))


    """
        Get amount of current votes

        Returns:
            Number of votes
    """
    def countTotalVotes(self):

        return reduce((lambda a, b: a + b), self.candidates.values())