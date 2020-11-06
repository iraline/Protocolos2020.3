import unittest
from VotingSession import VotingSession

class VotingSessionTest(unittest.TestCase):

    def setUp(self):

        self.MAX_VOTES = 3 
        self.DURATION = 10

        self.sessionMaxVotes =  VotingSession(
            sessionName='Melhor Pizza',
            candidates=['Calabresa', 'Mussarela'],
            sessionMode='maxVotes',
            maxVotes=self.MAX_VOTES
        )

        self.sessionDuration = VotingSession(
            sessionName='Melhor Pizza',
            candidates=['Calabresa', 'Mussarela'],
            sessionMode='duration',
            duration=self.DURATION
        )


    def test_can_compute_vote(self):

        userID = '1' 
        candidate = 'Calabresa'

        self.assertEqual(0, self.sessionMaxVotes.countTotalVotes())
        hasVotedSuccessfully = self.sessionMaxVotes.vote(userID, candidate)
        self.assertTrue(hasVotedSuccessfully)
        self.assertEqual(1, self.sessionMaxVotes.countTotalVotes())
        self.assertEqual(1, self.sessionMaxVotes.candidates[candidate])
        

    def test_cannot_vote_twice(self):

        userID = '1' 
        candidate = 'Calabresa'
        candidate2 = 'Mussarela'

        self.sessionMaxVotes.vote(userID, candidate)

        hasVotedSuccessfully = self.sessionMaxVotes.vote(userID, candidate)
        self.assertFalse(hasVotedSuccessfully)
        self.assertEqual(1, self.sessionMaxVotes.countTotalVotes())
        self.assertEqual(1, self.sessionMaxVotes.candidates[candidate])
        
        hasVotedSuccessfully = self.sessionMaxVotes.vote(userID, candidate2)
        self.assertFalse(hasVotedSuccessfully)
        self.assertEqual(1, self.sessionMaxVotes.countTotalVotes())
        self.assertEqual(0, self.sessionMaxVotes.candidates[candidate2])


    def test_can_count_total_votes_correctly(self):

        candidate = 'Calabresa'

        self.assertEqual(0, self.sessionMaxVotes.countTotalVotes())
        
        self.sessionMaxVotes.candidates[candidate] = self.MAX_VOTES -1
        self.assertEqual(self.MAX_VOTES -1, self.sessionMaxVotes.countTotalVotes())


    def test_finishes_session_when_max_votes_is_reached(self):
        
        userID = 'user'
        candidate = "Calabresa"
        self.sessionMaxVotes.candidates[candidate] = self.MAX_VOTES

        self.assertTrue(self.sessionMaxVotes.hasFinished())
        self.assertFalse(self.sessionMaxVotes.vote(userID, candidate))
        self.assertEqual(self.MAX_VOTES, self.sessionMaxVotes.countTotalVotes())


