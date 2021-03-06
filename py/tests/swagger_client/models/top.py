# coding: utf-8

"""
    Aeternity Epoch

    This is the [Aeternity](https://www.aeternity.com/) Epoch API.

    OpenAPI spec version: 1.0.0
    Contact: apiteam@aeternity.com
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from pprint import pformat
from six import iteritems
import re


class Top(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """


    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'height': 'int',
        'hash': 'str',
        'prev_hash': 'str',
        'state_hash': 'str',
        'txs_hash': 'str',
        'difficulty': 'int',
        'nonce': 'int',
        'time': 'int',
        'version': 'int',
        'pow': 'str'
    }

    attribute_map = {
        'height': 'height',
        'hash': 'hash',
        'prev_hash': 'prev_hash',
        'state_hash': 'state_hash',
        'txs_hash': 'txs_hash',
        'difficulty': 'difficulty',
        'nonce': 'nonce',
        'time': 'time',
        'version': 'version',
        'pow': 'pow'
    }

    def __init__(self, height=None, hash=None, prev_hash=None, state_hash=None, txs_hash=None, difficulty=None, nonce=None, time=None, version=None, pow=None):
        """
        Top - a model defined in Swagger
        """

        self._height = None
        self._hash = None
        self._prev_hash = None
        self._state_hash = None
        self._txs_hash = None
        self._difficulty = None
        self._nonce = None
        self._time = None
        self._version = None
        self._pow = None

        if height is not None:
          self.height = height
        if hash is not None:
          self.hash = hash
        if prev_hash is not None:
          self.prev_hash = prev_hash
        if state_hash is not None:
          self.state_hash = state_hash
        if txs_hash is not None:
          self.txs_hash = txs_hash
        if difficulty is not None:
          self.difficulty = difficulty
        if nonce is not None:
          self.nonce = nonce
        if time is not None:
          self.time = time
        if version is not None:
          self.version = version
        if pow is not None:
          self.pow = pow

    @property
    def height(self):
        """
        Gets the height of this Top.

        :return: The height of this Top.
        :rtype: int
        """
        return self._height

    @height.setter
    def height(self, height):
        """
        Sets the height of this Top.

        :param height: The height of this Top.
        :type: int
        """

        self._height = height

    @property
    def hash(self):
        """
        Gets the hash of this Top.

        :return: The hash of this Top.
        :rtype: str
        """
        return self._hash

    @hash.setter
    def hash(self, hash):
        """
        Sets the hash of this Top.

        :param hash: The hash of this Top.
        :type: str
        """

        self._hash = hash

    @property
    def prev_hash(self):
        """
        Gets the prev_hash of this Top.

        :return: The prev_hash of this Top.
        :rtype: str
        """
        return self._prev_hash

    @prev_hash.setter
    def prev_hash(self, prev_hash):
        """
        Sets the prev_hash of this Top.

        :param prev_hash: The prev_hash of this Top.
        :type: str
        """

        self._prev_hash = prev_hash

    @property
    def state_hash(self):
        """
        Gets the state_hash of this Top.

        :return: The state_hash of this Top.
        :rtype: str
        """
        return self._state_hash

    @state_hash.setter
    def state_hash(self, state_hash):
        """
        Sets the state_hash of this Top.

        :param state_hash: The state_hash of this Top.
        :type: str
        """

        self._state_hash = state_hash

    @property
    def txs_hash(self):
        """
        Gets the txs_hash of this Top.

        :return: The txs_hash of this Top.
        :rtype: str
        """
        return self._txs_hash

    @txs_hash.setter
    def txs_hash(self, txs_hash):
        """
        Sets the txs_hash of this Top.

        :param txs_hash: The txs_hash of this Top.
        :type: str
        """

        self._txs_hash = txs_hash

    @property
    def difficulty(self):
        """
        Gets the difficulty of this Top.

        :return: The difficulty of this Top.
        :rtype: int
        """
        return self._difficulty

    @difficulty.setter
    def difficulty(self, difficulty):
        """
        Sets the difficulty of this Top.

        :param difficulty: The difficulty of this Top.
        :type: int
        """

        self._difficulty = difficulty

    @property
    def nonce(self):
        """
        Gets the nonce of this Top.

        :return: The nonce of this Top.
        :rtype: int
        """
        return self._nonce

    @nonce.setter
    def nonce(self, nonce):
        """
        Sets the nonce of this Top.

        :param nonce: The nonce of this Top.
        :type: int
        """

        self._nonce = nonce

    @property
    def time(self):
        """
        Gets the time of this Top.

        :return: The time of this Top.
        :rtype: int
        """
        return self._time

    @time.setter
    def time(self, time):
        """
        Sets the time of this Top.

        :param time: The time of this Top.
        :type: int
        """

        self._time = time

    @property
    def version(self):
        """
        Gets the version of this Top.

        :return: The version of this Top.
        :rtype: int
        """
        return self._version

    @version.setter
    def version(self, version):
        """
        Sets the version of this Top.

        :param version: The version of this Top.
        :type: int
        """

        self._version = version

    @property
    def pow(self):
        """
        Gets the pow of this Top.

        :return: The pow of this Top.
        :rtype: str
        """
        return self._pow

    @pow.setter
    def pow(self, pow):
        """
        Sets the pow of this Top.

        :param pow: The pow of this Top.
        :type: str
        """

        self._pow = pow

    def to_dict(self):
        """
        Returns the model properties as a dict
        """
        result = {}

        for attr, _ in iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """
        Returns the string representation of the model
        """
        return pformat(self.to_dict())

    def __repr__(self):
        """
        For `print` and `pprint`
        """
        return self.to_str()

    def __eq__(self, other):
        """
        Returns true if both objects are equal
        """
        if not isinstance(other, Top):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        Returns true if both objects are not equal
        """
        return not self == other
