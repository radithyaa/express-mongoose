import { Router, Request, Response } from 'express';
import { User } from '../models/User';
import { authenticate, authorize } from '../middleware/auth';
import { validatePasswordChange, validateProfileUpdate } from '../middleware/validation';
import { 
  IChangePasswordRequest, 
  IUpdateProfileRequest, 
  IApiResponse, 
  IApiError,
  IPaginatedResponse,
  IUser
} from '../types';

const router = Router();

// @route   GET /api/users/profile
// @desc    Get user profile
// @access  Private
router.get('/profile', authenticate, async (req: Request, res: Response<IApiResponse<{ user: any }> | IApiError>): Promise<void> => {
  try {
    const response: IApiResponse<{ user: any }> = {
      success: true,
      message: 'Profile retrieved successfully',
      data: {
        user: req.user
      }
    };
    res.json(response);
  } catch (error) {
    console.error('Get profile error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to get user profile'
    };
    res.status(500).json(apiError);
  }
});

// @route   PUT /api/users/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', authenticate, validateProfileUpdate, async (req: Request<{}, IApiResponse<{ user: any }>, IUpdateProfileRequest>, res: Response<IApiResponse<{ user: any }> | IApiError>): Promise<void> => {
  try {
    const { firstName, lastName, username } = req.body;
    const userId = req.user?._id;

    if (!userId) {
      const error: IApiError = {
        error: 'Authentication required',
        message: 'User not authenticated'
      };
      res.status(401).json(error);
      return;
    }

    // Check if username is being changed and if it's already taken
    if (username && username !== req.user?.username) {
      const existingUser = await User.findOne({ username, _id: { $ne: userId } });
      if (existingUser) {
        const error: IApiError = {
          error: 'Username already exists',
          message: 'This username is already taken'
        };
        res.status(409).json(error);
        return;
      }
    }

    // Update user profile
    const updateData: Partial<IUpdateProfileRequest> = {};
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (username) updateData.username = username;

    const user = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password -refreshTokens');

    if (!user) {
      const error: IApiError = {
        error: 'User not found',
        message: 'User account not found'
      };
      res.status(404).json(error);
      return;
    }

    const response: IApiResponse<{ user: any }> = {
      success: true,
      message: 'Profile updated successfully',
      data: {
        user
      }
    };
    res.json(response);
  } catch (error) {
    console.error('Update profile error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to update profile'
    };
    res.status(500).json(apiError);
  }
});

// @route   PUT /api/users/change-password
// @desc    Change user password
// @access  Private
router.put('/change-password', authenticate, validatePasswordChange, async (req: Request<{}, IApiResponse, IChangePasswordRequest>, res: Response<IApiResponse | IApiError>): Promise<void> => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user?._id;

    if (!userId) {
      const error: IApiError = {
        error: 'Authentication required',
        message: 'User not authenticated'
      };
      res.status(401).json(error);
      return;
    }

    // Find user with password
    const user = await User.findById(userId);
    if (!user) {
      const error: IApiError = {
        error: 'User not found',
        message: 'User account not found'
      };
      res.status(404).json(error);
      return;
    }

    // Verify current password
    const isCurrentPasswordValid = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordValid) {
      const error: IApiError = {
        error: 'Invalid password',
        message: 'Current password is incorrect'
      };
      res.status(400).json(error);
      return;
    }

    // Update password
    user.password = newPassword;
    await user.save();

    const response: IApiResponse = {
      success: true,
      message: 'Password changed successfully'
    };
    res.json(response);
  } catch (error) {
    console.error('Change password error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to change password'
    };
    res.status(500).json(apiError);
  }
});

// @route   DELETE /api/users/account
// @desc    Deactivate user account
// @access  Private
router.delete('/account', authenticate, async (req: Request, res: Response<IApiResponse | IApiError>): Promise<void> => {
  try {
    const userId = req.user?._id;

    if (!userId) {
      const error: IApiError = {
        error: 'Authentication required',
        message: 'User not authenticated'
      };
      res.status(401).json(error);
      return;
    }

    // Deactivate account instead of deleting
    const user = await User.findByIdAndUpdate(
      userId,
      { 
        isActive: false,
        refreshTokens: [] // Clear all refresh tokens
      },
      { new: true }
    ).select('-password -refreshTokens');

    if (!user) {
      const error: IApiError = {
        error: 'User not found',
        message: 'User account not found'
      };
      res.status(404).json(error);
      return;
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    const response: IApiResponse = {
      success: true,
      message: 'Account deactivated successfully'
    };
    res.json(response);
  } catch (error) {
    console.error('Deactivate account error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to deactivate account'
    };
    res.status(500).json(apiError);
  }
});

// @route   GET /api/users
// @desc    Get all users (Admin only)
// @access  Private/Admin
router.get('/', authenticate, authorize('admin'), async (req: Request, res: Response<IApiResponse<IPaginatedResponse<any>> | IApiError>): Promise<void> => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const skip = (page - 1) * limit;

    // Build query
    const query: any = {};
    if (req.query.search) {
      query.$or = [
        { username: { $regex: req.query.search, $options: 'i' } },
        { email: { $regex: req.query.search, $options: 'i' } },
        { firstName: { $regex: req.query.search, $options: 'i' } },
        { lastName: { $regex: req.query.search, $options: 'i' } }
      ];
    }
    if (req.query.role) {
      query.role = req.query.role;
    }
    if (req.query.isActive !== undefined) {
      query.isActive = req.query.isActive === 'true';
    }

    // Get users with pagination
    const users = await User.find(query)
      .select('-password -refreshTokens')
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);

    // Get total count
    const total = await User.countDocuments(query);

    const response: IApiResponse<IPaginatedResponse<any>> = {
      success: true,
      message: 'Users retrieved successfully',
      data: {
        data: users,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      }
    };
    res.json(response);
  } catch (error) {
    console.error('Get users error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to get users'
    };
    res.status(500).json(apiError);
  }
});

// @route   PUT /api/users/:id/role
// @desc    Update user role (Admin only)
// @access  Private/Admin
router.put('/:id/role', authenticate, authorize('admin'), async (req: Request<{ id: string }, IApiResponse<{ user: any }>, { role: string }>, res: Response<IApiResponse<{ user: any }> | IApiError>): Promise<void> => {
  try {
    const { role } = req.body;
    const userId = req.params.id;

    if (!['user', 'admin', 'moderator'].includes(role)) {
      const error: IApiError = {
        error: 'Invalid role',
        message: 'Role must be user, admin, or moderator'
      };
      res.status(400).json(error);
      return;
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true, runValidators: true }
    ).select('-password -refreshTokens');

    if (!user) {
      const error: IApiError = {
        error: 'User not found',
        message: 'User account not found'
      };
      res.status(404).json(error);
      return;
    }

    const response: IApiResponse<{ user: any }> = {
      success: true,
      message: 'User role updated successfully',
      data: {
        user
      }
    };
    res.json(response);
  } catch (error) {
    console.error('Update user role error:', error);
    const apiError: IApiError = {
      error: 'Internal server error',
      message: 'Failed to update user role'
    };
    res.status(500).json(apiError);
  }
});

export default router;